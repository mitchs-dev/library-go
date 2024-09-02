// packageName: processor

/*
Package processor provides functions for file and directory manipulation
*/
package processor

import (
	"bufio"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	cp "github.com/otiai10/copy"
	log "github.com/sirupsen/logrus"
)

var Filename string

/*
Uploading + tmpdir cleanup functions
*/

// Use: UploadHandler |DESCRIPTION| Handles file uploaFilenameds and returns the file path and file of the uploaded file |ARGS| w (http.ResponseWriter), r (*http.Request), temporaryUploadsDirectory (string)
func UploadHandler(w http.ResponseWriter, r *http.Request, temporaryUploadsDirectory string) string {
	log.Debug("File upload in progress")
	if r.Method != "PUT" {
		log.Error("Invalid method: ", r.Method)
		log.Warn("File Upload cancelled")
		return "CLIENTERROR,405,Method not allowed"
	}
	file, fileHeader, err := r.FormFile("file")
	if err != nil {
		log.Error("Error retrieving file: ", err)
		return "ERROR"
	}
	fileSize := fileHeader.Size
	buff := make([]byte, fileSize)
	_, err = file.Read(buff)
	if err != nil {
		log.Error("Error reading upload file: ", err)
		return "ERROR"
	}
	// Create the uploads folder if it doesn't
	// already exist
	err = os.MkdirAll(temporaryUploadsDirectory, os.ModePerm)
	if err != nil {
		log.Error("Error creating uploads folder: ", err)
		return "ERROR"
	}
	Filename = temporaryUploadsDirectory + "/" + fileHeader.Filename
	// Create a new file in the uploads directory
	dst, err := os.Create(Filename)
	if err != nil {
		log.Error("Error creating file: ", err)
		return "ERROR"
	}
	defer dst.Close()

	os.WriteFile(Filename, buff, 0644)
	log.Debug("Upload process complete")
	log.Debug("File uploaded as: ", Filename)
	return Filename
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
		log.Error("Error deleting file: ", err)
		return false
	}
	return true

}

// Delete a specified directory
func DirectoryDelete(directoryName string) bool {
	err := os.RemoveAll(directoryName)
	if err != nil {
		log.Error("Error deleting directory: ", err)
		return false
	}
	return true

}

// Create a specified file with specified contents as a byte array
func CreateFileAsByte(Filename string, contentType []byte) bool {
	log.Debug("Creating file: ", Filename)
	file, err := os.Create(Filename)
	if err != nil {
		log.Error("Error creating file: ", err)
		return false
	}
	err = os.WriteFile(Filename, contentType, 0644)
	if err != nil {
		log.Error("Error writing file: ", err)
		return false
	}
	log.Debug("Successfully created file")
	defer file.Close()
	return true
}

// Create a specified file with specified contents as a string
func CreateFile(Filename string, contentType string) bool {
	log.Debug("Creating file: ", Filename)
	file, err := os.Create(Filename)
	if err != nil {
		log.Error("Error creating file: ", err)
		return false
	}
	err = os.WriteFile(Filename, []byte(contentType), 0644)
	if err != nil {
		log.Error("Error writing file: ", err)
		return false
	}
	log.Debug("Successfully created file")
	defer file.Close()
	return true
}

// Create a specified directory
func CreateDirectory(directoryName string) bool {
	log.Debug("Creating directory: ", directoryName)
	err := os.MkdirAll(directoryName, os.ModePerm)
	if err != nil {
		log.Error("Error creating directory: ", err)
		return false
	}
	log.Debug("Successfully created directory")
	return true
}

// Copy a specified file to a specified destination
func CopyFile(source string, destination string) bool {
	log.Debug("Copying file: ", source+" to: "+destination)
	oldFile, err := os.ReadFile(source)
	if err != nil {
		log.Error("Error reading source file: ", err)
		return false
	}
	file, err := os.Create(destination)
	if err != nil {
		log.Error("Error creating destination file: ", err)
		return false
	}
	defer file.Close()
	err = os.WriteFile(destination, oldFile, 0644)
	if err != nil {
		log.Error("Error writing to destination file: ", err)
		return false
	}
	log.Debug("Successfully copied file")
	return true
}

// Copies a directory to a source destination
func CopyDirectory(source string, destination string) bool {
	log.Debug("Copying directory: ", source+" to: "+destination)
	err := cp.Copy(source, destination)
	if err != nil {
		log.Error("Error copying directory: ", err)
		return false
	}
	log.Debug("Successfully copied directory")
	return true
}

// Read a specified file and return the contents as a byte array
func ReadFile(Filename string) []byte {
	log.Debug("Reading file: ", Filename)
	file, err := os.ReadFile(Filename)
	if err != nil {
		log.Error("Error reading file: ", err)
		return nil
	}
	log.Debug("Successfully read file")
	return file
}

// Provides a count of substrings given from provided string and separator(s)
func GetSubstringCount(str string, seps ...string) (i int) {
	for _, sep := range seps {
		i += strings.Count(str, sep)
	}
	return i
}

// Convert a files contents to url.Values
func FileToURLValues(filePath string) (url.Values, error) {
	errorMessagePrefix := "FileToURLValues: "
	file, err := os.Open(filePath)
	if err != nil {
		return nil, errors.New(errorMessagePrefix + err.Error())
	}
	defer file.Close()

	values := url.Values{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, errors.New(errorMessagePrefix + fmt.Sprintf("invalid line: %s", line))
		}

		key := parts[0]
		value := strings.Trim(parts[1], "'") // remove single quotes if present
		values.Add(key, value)
	}

	if err := scanner.Err(); err != nil {
		return nil, errors.New(errorMessagePrefix + err.Error())
	}

	return values, nil
}

// Check if a directory or file exists
func DirectoryOrFileExists(entryName string) bool {
	_, err := os.Stat(entryName)
	return !os.IsNotExist(err)
}
