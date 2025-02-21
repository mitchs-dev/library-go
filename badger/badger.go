// Package name: badger

/*
	Package badger provides a wrapper functions for Badger database interactions.

REQUIRED VARIABLES: (SET ON INIT)

	DataDir       string
	OptionsDir    string
	TimeZone      string
	LogPrefix     string
	EncryptionKey string

Example:

	func badgerInit() {
		c.Get(globals.ConfigFile)
		badger.DataDir = c.Badger.DataDir
		badger.OptionsDir = c.Badger.OptionsDir
		badger.TimeZone = c.TimeZone
		badger.LogPrefix = c.LogPrefix
		badger.EncryptionKey = globals.EncryptionKey
		badger.EncryptionIV = globals.EncryptionIV
	}
*/
package badger

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/dgraph-io/badger"
	"github.com/mitchs-dev/library-go/encryption"
	"github.com/mitchs-dev/library-go/loggingFormatter"
	"github.com/sirupsen/logrus"
)

var (
	b    *CommandsRepository
	once sync.Once
	// Set on init
	DataDir       string
	OptionsDir    string
	TimeZone      string
	LogPrefix     string
	EncryptionKey []byte
)

func badgerConfigCheck() error {
	if DataDir == "" {
		return errors.New("badger data directory is empty")
	}
	if OptionsDir == "" {
		return errors.New("badger options directory is empty")
	}
	if TimeZone == "" {
		return errors.New("badger timezone is empty")
	}
	if LogPrefix == "" {
		return errors.New("badger log prefix is empty")
	}
	if EncryptionKey == nil {
		return errors.New("badger encryption key is empty")
	}
	return nil
}

func DBConnectionInit() error {
	if err := badgerConfigCheck(); err != nil {
		return errors.New("error when checking Badger configuration: " + err.Error())
	}
	var dbInitError error
	once.Do(func() {
		var err error
		b, err = NewCommandsRepository(DataDir)
		if err != nil {
			dbInitError = errors.New("error when opening Badger database: " + err.Error())
		}
		if b == nil {
			dbInitError = errors.New("error when opening Badger database: badger is nil")
		}
	})

	if dbInitError != nil {
		return dbInitError
	}
	return nil
}

func GetDB() *CommandsRepository {
	if b == nil {
		DBConnectionInit()
	}
	return b
}

type Command struct {
	Key   []byte
	Value []byte
}

type Repository interface {
	GetAll() ([]Command, error)
	Get(key []byte) ([]byte, error)
	Set(key []byte, value []byte) error
	Delete(key []byte) error
	Iterate(key []byte) ([]Command, error)
}

type CommandsRepository struct {
	db *badger.DB
}

func NewCommandsRepository(dbPath string) (*CommandsRepository, error) {
	options := badger.DefaultOptions(OptionsDir)
	logger := logrus.New()
	logger.SetFormatter(&loggingFormatter.JSONFormatter{
		Timezone: TimeZone,
		Prefix:   LogPrefix,
	})
	options.Logger = logger
	db, err := badger.Open(options)
	if err != nil {
		return nil, fmt.Errorf("error when opening Badger database: %w", err)
	}
	return &CommandsRepository{db: db}, nil
}

func (b *CommandsRepository) Close() error {
	return b.db.Close()
}

func (b *CommandsRepository) GetAll() ([]Command, error) {
	var cmds []Command
	err := b.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			err := item.Value(func(v []byte) error {
				cmds = append(cmds, Command{Key: k, Value: v})
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cmds, nil
}

func (b *CommandsRepository) Set(k, v []byte) error {

	vValueEnc, err := encryption.Encrypt(v, EncryptionKey, true)
	if err != nil {
		return err
	}
	v = vValueEnc.([]byte)
	err = b.db.Update(func(txn *badger.Txn) error {
		err := txn.Set(k, v)
		return err
	})
	return err
}

func (b *CommandsRepository) Get(k []byte) ([]byte, error) {
	var v []byte
	err := b.db.View(func(txn *badger.Txn) error {
		i, err := txn.Get(k)
		if err != nil {
			return err
		}
		v, err = i.ValueCopy(v)
		return err
	})
	if err != nil {
		return nil, err
	} else {
		vValueDec, err := encryption.Decrypt(v, EncryptionKey, true)
		if err != nil {
			return nil, err
		}
		v = []byte(vValueDec)
		return v, nil
	}
}

func (b *CommandsRepository) Delete(k []byte) error {
	err := b.db.Update(func(txn *badger.Txn) error {
		err := txn.Delete(k)
		return err
	})
	return err
}

func (b *CommandsRepository) Iterate(prefix []byte) ([]Command, error) {
	var cmds []Command
	err := b.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchSize = 10
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Seek(prefix); it.Valid(); it.Next() {
			item := it.Item()
			k := item.Key()
			v, err := item.ValueCopy(nil)
			if err != nil {
				return err
			}
			vDecrypt, err := encryption.Decrypt(v, EncryptionKey, true)
			if err != nil {
				return err
			}
			v = []byte(vDecrypt)
			if strings.Contains(string(k), string(prefix)) {
				logrus.Debug("Key matches prefix ("+string(prefix)+"): ", string(k))
				appendData := Command{
					Key:   k,
					Value: v,
				}
				cmds = append(cmds, appendData)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cmds, nil
}
