// packageName: processor

/*
Package processor provides functions for file and directory manipulation
*/
package processor

import (
	"fmt"
	"io"
	"os"
	"sync"

	cp "github.com/otiai10/copy"
	log "github.com/sirupsen/logrus"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// ProcessFilesConcurrently processes files concurrently using a specified function
func ProcessFilesConcurrently(filePaths []string, processFunc func(string) error, numWorkers int) error {
	taskCh := make(chan string, len(filePaths))
	errCh := make(chan error, len(filePaths))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range taskCh {
				if err := processFunc(filePath); err != nil {
					log.Errorf("Error processing file %s: %v", filePath, err)
					errCh <- err
				}
			}
		}()
	}

	for _, filePath := range filePaths {
		taskCh <- filePath
	}
	close(taskCh)

	wg.Wait()
	close(errCh)

	if len(errCh) > 0 {
		//Handle Errors
		return fmt.Errorf("one or more errors occured")
	}

	return nil
}

// Used for cleaning up the temporary uploads directory
func CleanupUploadsDirectory(temporaryUploadsDirectory string) bool {
	log.Debug("Cleaning uploads directory")
	if DirectoryDelete(temporaryUploadsDirectory) {
		err := os.MkdirAll(temporaryUploadsDirectory, os.ModePerm)
		if err != nil {
			log.Error("Error creating uploads folder: ", err)
			return false
		}
		log.Debug("Uploads directory cleaned up")
		return true
	}
	return false
}

/*
File and directory manipulation functions
*/

// Delete a specified file
func FileDelete(Filename string) bool {
	err := os.Remove(Filename)
	if err != nil {
		log.Errorf("Error deleting file %s: %v", Filename, err)
		return false
	}
	log.Debugf("Successfully deleted file %s", Filename)
	return true
}

// Delete a specified directory
func DirectoryDelete(directoryName string) bool {
	err := os.RemoveAll(directoryName)
	if err != nil {
		log.Errorf("Error deleting directory %s: %v", directoryName, err)
		return false
	}
	log.Debugf("Successfully deleted directory %s", directoryName)
	return true

}

// Create a specified file with specified contents as a byte array
func CreateFileAsByte(Filename string, contentType []byte) bool {
	log.Debugf("Creating file: %s", Filename)
	file, err := os.Create(Filename)
	if err != nil {
		log.Errorf("Error creating file: %v", err)
		return false
	}
	err = os.WriteFile(Filename, contentType, 0644)
	if err != nil {
		log.Errorf("Error writing file: %v", err)
		return false
	}
	log.Debugf("Successfully created file: %s", Filename)
	defer file.Close()
	return true
}

// Create a specified file with specified contents as a string
func CreateFile(Filename string, contentType string) bool {
	log.Debugf("Creating file: %s", Filename)
	file, err := os.Create(Filename)
	if err != nil {
		log.Errorf("Error creating file: %v", err)
		return false
	}
	defer file.Close()
	err = os.WriteFile(Filename, []byte(contentType), 0644)
	if err != nil {
		log.Errorf("Error writing file: %v", err)
		return false
	}
	log.Debugf("Successfully created file: %s", Filename)
	return true
}

// Create a specified directory
func CreateDirectory(directoryName string) bool {
	log.Debugf("Creating directory: %s", directoryName)
	err := os.MkdirAll(directoryName, os.ModePerm)
	if err != nil {
		log.Errorf("Error creating directory: %v", err)
		return false
	}
	log.Debugf("Successfully created directory: %s", directoryName)
	return true
}

// Copy a specified file to a specified destination
func CopyFile(source string, destination string) bool {
	log.Debugf("Copying file: %s to: %s", source, destination)
	sourceFile, err := os.Open(source)
	if err != nil {
		log.Errorf("Error opening source file: %v", err)
		return false
	}
	defer sourceFile.Close()
	destFile, err := os.Create(destination)
	if err != nil {
		log.Errorf("Error creating destination file: %v", err)
		return false
	}
	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	_, err = io.CopyBuffer(destFile, sourceFile, buf)
	if err != nil {
		log.Errorf("Error copying file: %v", err)
		return false
	}
	bufPool.Put(bufPtr)
	log.Debugf("Successfully copied file: %s to: %s", source, destination)
	return true
}

// Copies a directory to a source destination
func CopyDirectory(source string, destination string) bool {
	log.Debugf("Copying directory: %s to: %s", source, destination)
	err := cp.Copy(source, destination)
	if err != nil {
		log.Errorf("Error copying directory: %v", err)
		return false
	}
	log.Debugf("Successfully copied directory: %s to: %s", source, destination)
	return true
}

// Read a specified file and return the contents as a byte array
func ReadFile(Filename string) []byte {
	log.Debugf("Reading file: %s", Filename)
	file, err := os.ReadFile(Filename)
	if err != nil {
		log.Errorf("Error reading file: %v", err)
		return nil
	}
	log.Debugf("Successfully read file: %s", Filename)
	return file
}

// Check if a directory or file exists
func DirectoryOrFileExists(entryName string) bool {
	_, err := os.Stat(entryName)
	log.Debugf("Checking if %s exists", entryName)
	return !os.IsNotExist(err)
}
