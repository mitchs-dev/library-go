// packageName: logRotation

/*
This package is used to rotate log files. This package is designed to be used with the CronJob function as the entrypoint.
*/
package logRotation

import (
	"io"
	"os"

	"github.com/inhies/go-bytesize"
	"github.com/mitchs-dev/library-go/generator"
	"github.com/mitchs-dev/library-go/processor"
	log "github.com/sirupsen/logrus"
)

// Set the log archive suffix
func setLogArchiveSuffix(appName string) string {
	return "-" + appName + "-archive.log"
}

// CronJob is the entrypoint for this package. This function is designed to be called by the CronJob function in the cron package.
func CronJob(timeZone string, cronSessionToken string, appName string, logFileEnabled bool, logRotationEnabled bool, logFilePath string, logArchivePath string, maxFileSize string, maxFileCount int) bool {
	if logFileEnabled {
		if logRotationEnabled {
			log.Debug("Running log rotation (Session: " + cronSessionToken + ")")
			if !run(timeZone, appName, logFilePath, logArchivePath, maxFileSize, maxFileCount) {
				return false
			}
		}
	}
	return true
}

// Run is the main function for this package. This function is designed to be called by the CronJob function.
func run(timeZone string, appName string, logFilePath string, logArchivePath string, maxFileSize string, maxFileCount int) bool {
	// Convert maxFileSize to bytes
	maxFileSizeBytes, err := bytesize.Parse(maxFileSize)
	// Convert maxFileSize to int64
	if err != nil {
		log.Error("Failed to parse max file size: ", err)
		return false
	}
	maxFileSizeBytesInt64 := int64(maxFileSizeBytes)
	// Check if log file has reached the maximum size
	file, err := os.Stat(logFilePath)
	if err != nil {
		return false
	}
	// Check if log file has reached the maximum size
	if file.Size() >= maxFileSizeBytesInt64 {
		os.MkdirAll(logArchivePath, os.ModePerm)
		// Check if the number of log files has reached the maximum
		if checkAndRemoveOldestArchivedLogFile(appName, logArchivePath, maxFileCount) {
			// Rotate the log file if the function returns true
			rotateStatus, archivedLogFile := rotate(timeZone, appName, logFilePath, logArchivePath)
			if !rotateStatus {
				log.Error("Failed to rotate log file")
				return false
			}
			// Output to both stdout and a file
			_, err := os.Stat(logFilePath)
			if os.IsNotExist(err) {
				file, err := os.Create(logFilePath)
				if err != nil {
					log.Fatal("Failed to create log file: ", err)
					return false
				}
				defer file.Close()
			}
			logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				log.Fatal("Failed to open log file: ", err)
			}
			log.SetOutput(io.MultiWriter(os.Stdout, logFile))
			log.Info("Log file rotated (" + archivedLogFile + ") per log rotation configuration")
			return true
		} else {
			log.Debug("Number of log files has not reached the maximum")
			// Rotate the log file if the function returns true
			rotateStatus, archivedLogFile := rotate(timeZone, appName, logFilePath, logArchivePath)
			if !rotateStatus {
				log.Error("Failed to rotate log file")
				return false
			}
			// Output to both stdout and a file
			_, err := os.Stat(logFilePath)
			if os.IsNotExist(err) {
				file, err := os.Create(logFilePath)
				if err != nil {
					log.Fatal("Failed to create log file: ", err)
					return false
				}
				defer file.Close()
			}
			logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				log.Fatal("Failed to open log file: ", err)
			}
			log.SetOutput(io.MultiWriter(os.Stdout, logFile))
			log.Info("Log file rotated (" + archivedLogFile + ") per log rotation configuration")
			return true
		}
	}
	return false
}

// This function is used to rotate the log file and return a boolean and string. The boolean is used to determine if the log file was rotated. The string is used to return the path of the archived log
func rotate(timeZone string, appName string, logFilePath string, logArchivePath string) (bool, string) {
	generateFileName := generator.FileNameTimestamp(timeZone) + setLogArchiveSuffix(appName)
	archivedLogFile := logArchivePath + "/" + generateFileName
	if !processor.CopyFile(logFilePath, archivedLogFile) {
		return false, "ERROR"
	}
	if !processor.FileDelete(logFilePath) {
		return false, "ERROR"
	}
	if !processor.CreateFile(logFilePath, "") {
		return false, "ERROR"
	}
	return true, archivedLogFile
}

// Check if the number of log files has reached the maximum and delete the oldest log file if it has reached the maximum number
func checkAndRemoveOldestArchivedLogFile(appName string, logArchivePath string, maxFileCount int) bool {
	// Get the list of files in the archive directory
	archiveDirFileList, err := os.ReadDir(logArchivePath)
	if err != nil {
		log.Error("Failed to read archive directory: ", err)
		// Return false if the archive directory was not read due to an error
		return false
	}
	var archiveDirFileListFiltered []os.FileInfo
	// Filter out files that do not end with the log archive suffix
	for _, file := range archiveDirFileList {
		// Check if the file name ends with the log archive suffix
		if file.Name()[len(file.Name())-len(setLogArchiveSuffix(appName)):] == setLogArchiveSuffix(appName) {
			fileInfo, err := os.Stat(file.Name())
			if err != nil {
				log.Fatal(err)
			}
			archiveDirFileListFiltered = append(archiveDirFileListFiltered, fileInfo)
		}
	}
	// Check if the number of log files has reached the maximum
	if len(archiveDirFileListFiltered) >= maxFileCount {
		// Delete the oldest log file
		oldestFile := archiveDirFileListFiltered[0]
		for _, file := range archiveDirFileListFiltered {
			if file.ModTime().Before(oldestFile.ModTime()) {
				oldestFile = file
			}
		}
		err := os.Remove(logArchivePath + "/" + oldestFile.Name())
		if err != nil {
			log.Error("Failed to delete oldest log file: ", err)
			// Return false if the oldest log file was not deleted due to an error
			return false
		}
		// Return true if the oldest log file was deleted
		log.Info("Deleted Oldest log file in archive (" + oldestFile.Name() + ") to meet maximum log file count limit")
		return true
	} else {
		// Return false if the number of log files has not reached the maximum
		return false
	}
}
