// packageName: archiver

/*
Package provides archiving functions
*/
package archiver

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

func Extract(ArchiveFile string, destinationPath string) ([]string, error) {
	var fileList []string
	r, err := os.Open(ArchiveFile)
	if err != nil {
		log.Error("Error opening Archive: ", ArchiveFile, ": ", err)
		return []string{"ERROR"}, err
	}
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return []string{"ERROR"}, err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()

		switch {

		// if no more files are found return
		case err == io.EOF:
			log.Debug("Extracted ", ArchiveFile, " to ", destinationPath)
			return fileList, err

		// return any other error
		case err != nil:
			return []string{"ERROR"}, err

		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}

		// the target location where the dir/file should be created
		target := filepath.Join(destinationPath, header.Name)
		err = sanitizeExtractPath(header.Name, destinationPath)
		if err != nil {
			return []string{"ERROR"}, err
		}

		// the following switch could also be done using fi.Mode(), not sure if there
		// a benefit of using one vs. the other.
		// fi := header.FileInfo()

		// check the file type

		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					log.Error("Error creating directory during archive extraction: ", err)
					return []string{"ERROR"}, err
				} else {
					log.Debug("Created directory during archive extraction: ", target)
				}
			}

		// if it's a file create it
		case tar.TypeReg:
			baseFilePath := filepath.Dir(target)
			if _, err := os.Stat(baseFilePath); err != nil {
				if err := os.MkdirAll(baseFilePath, 0755); err != nil {
					log.Error("Error creating directory for file during archive extraction: ", err)
					return []string{"ERROR"}, err
				}
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				log.Error("Error opening file during archive extraction: ", err)
				return []string{"ERROR"}, err
			}

			// copy over contents
			if _, err := io.Copy(f, tr); err != nil {
				log.Error("Error copying file during archive extraction: ", err)
				return []string{"ERROR"}, err
			}

			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			f.Close()
			fileList = append(fileList, header.Name)
			log.Debug("Added ", header.Name, " to file list for Archive: ", ArchiveFile)
		}

	}
}

// Patch for Zip Slip Vuln: https://security.snyk.io/research/zip-slip-vulnerability
func sanitizeExtractPath(filePath string, destination string) error {
	destpath := filepath.Join(destination, filePath)
	if !strings.HasPrefix(destpath, filepath.Clean(destination)+string(os.PathSeparator)) {
		return fmt.Errorf("%s: illegal file path", filePath)
	}
	return nil
}

func Archive(filePaths []string, destinationFile string) bool {
	getOriginalDirectory, err := os.Getwd()
	if err != nil {
		log.Error("Error getting current directory: ", err)
		return false
	}
	log.Debug("Files to be archived: ", filePaths)
	file, err := os.Create(destinationFile)
	if err != nil {
		log.Error("Could not create tarball file: ", err)
		return false
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	for _, filePath := range filePaths {
		err := addFileToTarWriter(filePath, tarWriter)
		if err != nil {
			log.Error("Could not write to tarball file: ", err)
			return false
		}
	}
	os.Chdir(getOriginalDirectory)
	log.Debug("Archive is available at: ", destinationFile)
	return true

}

func addFileToTarWriter(filePath string, tarWriter *tar.Writer) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	header := &tar.Header{
		Name:    filePath,
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	err = tarWriter.WriteHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(tarWriter, file)
	if err != nil {
		return err
	}

	return nil
}
