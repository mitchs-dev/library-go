// packageName: loggingFormatter

/*
This package is used provide a standardized format for loggers using the sirupsen/logrus package.
*/
package loggingFormatter

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"

	jsoniter "github.com/json-iterator/go"
	"github.com/mitchs-dev/library-go/generator"
	"github.com/sirupsen/logrus"
)

const (
	defaultLogFormat       = "%lBracket%%time%%vLine%%lvl%%vLine%%context%%rBracket%%sColon% %msg%\n"
	JSONLogFormat          = "{\"id\":\"%id%\",\"timestamp\":\"%time%\",\"level\":\"%lvl%\",\"context\":\"%context%\",\"message\":\"%msg%\"}\n"
	JSONLogMessageNoQuote  = "{\"id\":\"%id%\",\"timestamp\":\"%time%\",\"level\":\"%lvl%\",\"context\":\"%context%\",\"message\":%msg%}\n"
	defaultTimestampFormat = "2006-01-02T15:04:05"
)

// Formatter implements logrus.Formatter interface.
type Formatter struct {
	TimestampFormat string // Format string for timestamp
	LogFormat       string // Format string for log output
}

// Use: loggingFormatter.Formatter{} (Struct) |DESCRIPTION| Format building log message as standard text |ARGS|
func (f *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	output := f.LogFormat
	if output == "" {
		output = defaultLogFormat
	}

	timestampFormat := f.TimestampFormat
	if timestampFormat == "" {
		timestampFormat = defaultTimestampFormat
	}
	_, file, line, ok := runtime.Caller(7)
	if !ok {
		file = "unknown"
		line = 0
	}
	file = file[strings.LastIndex(file, "/")+1:]
	pkgLine := fmt.Sprintf("%s:%d", file, line)
	_, filePlusOne, linePlusOne, okPlusOne := runtime.Caller(8)
	if !okPlusOne {
		file = "unknown"
		line = 0
	}
	filePlusOne = filePlusOne[strings.LastIndex(filePlusOne, "/")+1:]
	pkgLinePlusOne := fmt.Sprintf("%s:%d", filePlusOne, linePlusOne)
	output = strings.Replace(output, "%lBracket%", "[", 1)
	// We specify 1 and 2 below as we do not want to accidentally replace a string in the message
	output = strings.Replace(output, "%vLine%", "|", 1)
	output = strings.Replace(output, "%vLine%", "|", 2)
	output = strings.Replace(output, "%rBracket%", "]", 1)
	output = strings.Replace(output, "%sColon%", ":", 1)
	output = strings.Replace(output, "%time%", entry.Time.Format(timestampFormat), 1)
	output = strings.Replace(output, "%msg%", entry.Message, 1)
	shortLevel := entry.Level.String()[0:4]
	level := strings.ToUpper(shortLevel)
	output = strings.Replace(output, "%lvl%", level, 1)
	output = strings.Replace(output, "%context%", pkgLine+"("+pkgLinePlusOne+")", 1)

	for k, val := range entry.Data {
		switch v := val.(type) {
		case string:
			output = strings.Replace(output, "%"+k+"%", v, 1)
		case int:
			s := strconv.Itoa(v)
			output = strings.Replace(output, "%"+k+"%", s, 1)
		case bool:
			s := strconv.FormatBool(v)
			output = strings.Replace(output, "%"+k+"%", s, 1)
		}
	}

	return []byte(output), nil
}

// JSON	logrus formatter for JSON output

// JSONFormatter formats logs into parsable json
type JSONFormatter struct {
	TimestampFormat string // Format string for timestamp
	Prefix          string // Prefix to write at the beginning of each line
	Timezone        string // Timezone to use for timestamps
	LogFormat       string // Format string for log output
	MessageNoQuote  bool   // If true, don't put the message field in quotes
	bufferPool      *sync.Pool
}

// NewJSONFormatter creates a new JSONFormatter
func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		},
	}
}

// LogEntry is the log entry structure for JSONFormatter
type LogEntry struct {
	ID      string        `json:"id"`
	Time    string        `json:"time"`
	Level   string        `json:"level"`
	Context string        `json:"context"`
	Message string        `json:"message"`
	Data    logrus.Fields `json:"data,omitempty"`
}

// Use: loggingFormatter.JSONFormatter{} (Struct) |DESCRIPTION| Format renders a single log entry as JSON |ARGS| Prefix (string), Timezone (string), MessageNoQuote (bool)
func (f *JSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	if f.bufferPool == nil {
		f.bufferPool = &sync.Pool{
			New: func() interface{} {
				return new(bytes.Buffer)
			},
		}
	}

	buffer := f.bufferPool.Get().(*bytes.Buffer)
	buffer.Reset()
	defer f.bufferPool.Put(buffer)

	logEntry := LogEntry{
		ID:      f.Prefix + generator.StringTimestamp(f.Timezone) + generator.RandomString(20),
		Time:    entry.Time.UTC().Format(f.TimestampFormat),
		Level:   entry.Level.String(),
		Message: entry.Message, // Initially set as string
		Context: getContext(),
		Data:    entry.Data,
	}

	if f.MessageNoQuote {
		logEntry.Message = entry.Message // Set as is, will be encoded raw
	}

	jsoniter.ConfigFastest.NewEncoder(buffer).Encode(logEntry)

	return buffer.Bytes(), nil
}

func getContext() string {
	_, file, line, ok := runtime.Caller(7)
	if !ok {
		return "unknown:0"
	}
	file = file[strings.LastIndex(file, "/")+1:]
	pkgLine := fmt.Sprintf("%s:%d", file, line)
	_, filePlusOne, linePlusOne, okPlusOne := runtime.Caller(8)
	if !okPlusOne {
		return "unknown:0"
	}
	filePlusOne = filePlusOne[strings.LastIndex(filePlusOne, "/")+1:]
	pkgLinePlusOne := fmt.Sprintf("%s:%d", filePlusOne, linePlusOne)
	return pkgLine + "(" + pkgLinePlusOne + ")"
}
