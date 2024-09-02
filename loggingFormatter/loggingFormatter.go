// packageName: loggingFormatter

/*
This package is used provide a standardized format for loggers using the sirupsen/logrus package.
*/
package loggingFormatter

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/mitchs-dev/library-go/generator"
	"github.com/sirupsen/logrus"
)

const (
	defaultLogFormat       = "%lBracket%%time%%vLine%%lvl%%rBracket%%sColon% %msg%\n"
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
	output = strings.Replace(output, "%lBracket%", "[", 1)
	output = strings.Replace(output, "%vLine%", "|", 1)
	output = strings.Replace(output, "%rBracket%", "]", 1)
	output = strings.Replace(output, "%sColon%", ":", 1)
	output = strings.Replace(output, "%time%", entry.Time.Format(timestampFormat), 1)
	output = strings.Replace(output, "%msg%", entry.Message, 1)
	shortLevel := entry.Level.String()[0:4]
	level := strings.ToUpper(shortLevel)
	output = strings.Replace(output, "%lvl%", level, 1)

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
}

// Use: loggingFormatter.JSONFormatter{} (Struct) |DESCRIPTION| Format renders a single log entry as JSON |ARGS| Prefix (string), Timezone (string), MessageNoQuote (bool)
func (f *JSONFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	output := f.LogFormat
	if output == "" {
		if f.MessageNoQuote {
			output = JSONLogMessageNoQuote
		} else {
			output = JSONLogFormat
		}
	}

	timestampFormat := f.TimestampFormat
	if timestampFormat == "" {
		timestampFormat = defaultTimestampFormat
	}
	if f.Prefix == "" {
		f.Prefix = "log-"
	}
	if f.Timezone == "" {
		f.Timezone = "UTC"
	}
	id := f.Prefix + generator.StringTimestamp(f.Timezone) + generator.RandomString(7)
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
	file = file[strings.LastIndex(file, "/")+1:]
	output = strings.Replace(output, "%id%", id, 1)
	output = strings.Replace(output, "%time%", entry.Time.In(generator.GetLocation(f.Timezone)).Format(timestampFormat), 1)
	output = strings.Replace(output, "%msg%", entry.Message, 1)
	output = strings.Replace(output, "%context%", pkgLine+"("+pkgLinePlusOne+")", 1)
	output = strings.Replace(output, "%lvl%", entry.Level.String(), 1)

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
