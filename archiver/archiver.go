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
	"sync"

	log "github.com/sirupsen/logrus"
)

// ArchiveError is an error type for archiving errors
type ArchiveError struct {
	Message string
	Err     error
}

var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 32*1024)
		return &buf
	},
}

// Error returns the error message
func (e *ArchiveError) Error() string {
	return fmt.Sprintf("archiver: %s: %v", e.Message, e.Err)
}

// ArchiveConcurrent creates a tarball of the files specified in filePaths and saves it to destinationFile
func ArchiveConcurrent(filePaths []string, destinationFile string, numWorkers int) error {
	file, err := os.Create(destinationFile)
	if err != nil {
		return fmt.Errorf("error creating archive file: %v", err)
	}
	defer file.Close()

	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	taskCh := make(chan string, len(filePaths))
	errCh := make(chan error, len(filePaths))
	var wg sync.WaitGroup

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(tw *tar.Writer) {
			defer wg.Done()
			for filePath := range taskCh {
				log.Debugf("Processing file: %s", filePath)
				err := filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
					if err != nil {
						return fmt.Errorf("error walking file path: %v", err)
					}
					if info.IsDir() {
						return nil
					}
					return addFileToTarWriter(path, tw)
				})
				if err != nil {
					errCh <- err
				}
			}
		}(tarWriter)
	}

	go func() {
		for _, filePath := range filePaths {
			taskCh <- filePath
		}
		close(taskCh)
	}()

	wg.Wait()
	close(errCh)

	if len(errCh) > 0 {
		errors := make([]error, 0, len(errCh))
		for err := range errCh {
			errors = append(errors, err)
		}
		return fmt.Errorf("one or more errors occurred: %v", errors)
	}

	return nil
}

// Extract extracts the contents of an archive file to a destination path
func Extract(ArchiveFile string, destinationPath string) ([]string, error) {
	var fileList []string
	r, err := os.Open(ArchiveFile)
	if err != nil {
		return nil, fmt.Errorf("error opening archive file: %v", err)
	}
	gzr, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("error creating gzip reader: %v", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)

	for {
		header, err := tr.Next()

		switch {

		// if no more files are found return
		case err == io.EOF:
			log.Debug("Extracted ", ArchiveFile, " to ", destinationPath)
			return fileList, nil

		// return any other error
		case err != nil:
			return nil, fmt.Errorf("error extracting tarball: %v", err)

		// if the header is nil, just skip it (not sure how this happens)
		case header == nil:
			continue
		}

		cleanedDest := filepath.Clean(destinationPath)
		// the target location where the dir/file should be created
		target := filepath.Join(destinationPath, header.Name)
		err = sanitizeExtractPath(header.Name, destinationPath, cleanedDest)
		if err != nil {
			return nil, fmt.Errorf("error extracting tarball: %v", err)
		}

		// check the file type

		switch header.Typeflag {
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return nil, fmt.Errorf("error creating directory during archive extraction: %v", err)
				} else {
					log.Debug("Created directory during archive extraction: ", target)
				}
			}

		// if it's a file create it
		case tar.TypeReg:
			baseFilePath := filepath.Dir(target)
			if _, err := os.Stat(baseFilePath); err != nil {
				if err := os.MkdirAll(baseFilePath, 0755); err != nil {
					return nil, fmt.Errorf("error creating directory for file during archive extraction: %v", err)
				}
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return nil, fmt.Errorf("error creating file during archive extraction: %v", err)
			}

			// copy over contents
			bufPtr := bufPool.Get().(*[]byte)
			buf := *bufPtr
			_, err = io.CopyBuffer(f, tr, buf)
			bufPool.Put(bufPtr)
			if err != nil {
				return nil, fmt.Errorf("error copying file during archive extraction: %v", err)
			}

			// manually close here after each file operation; deferring would cause each file close
			// to wait until all operations have completed.
			f.Close()
			fileList = append(fileList, header.Name)
			log.Debug("Added ", header.Name, " to file list for Archive: ", ArchiveFile)
		}

	}
}

// Patch for Zip Slip Vuln: https://security.snyk.io/research/zip-slip-vulnerability
func sanitizeExtractPath(filePath string, destination string, cleanedDest string) error {
	destpath := filepath.Join(destination, filePath)
	if !strings.HasPrefix(destpath, cleanedDest+string(os.PathSeparator)) {
		return fmt.Errorf("%s: illegal file path", filePath)
	}
	return nil
}

// Archive creates a tarball of the files specified in filePaths and saves it to destinationFile
// You can set the compression level to 0 (no compression) to 9 (best compression)
func Archive(filePaths []string, destinationFile string, compressionLevel int) error {
	log.Debug("Files to be archived: ", filePaths)
	file, err := os.Create(destinationFile)
	if err != nil {
		log.Error("Could not create tarball file: ", err)
		return &ArchiveError{Message: "Could not create tarball file", Err: err}
	}
	defer file.Close()

	gzipWriter, err := gzip.NewWriterLevel(file, compressionLevel)
	if err != nil {
		return &ArchiveError{Message: "Error creating gzip writer", Err: err}
	}
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	for _, filePath := range filePaths {
		err := filepath.Walk(filePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return &ArchiveError{Message: "Error walking file path", Err: err}
			}
			if info.IsDir() {
				return nil
			}
			return addFileToTarWriter(path, tarWriter)
		})
		if err != nil {
			return &ArchiveError{Message: "Error walking file path", Err: err}
		}
	}
	log.Debug("Archive is available at: ", destinationFile)
	return nil

}

// addFileToTarWriter adds a file to a tarball
func addFileToTarWriter(filePath string, tarWriter *tar.Writer) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %v", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("error stating file: %v", err)
	}

	header := &tar.Header{
		Name:    filePath,
		Size:    stat.Size(),
		Mode:    int64(stat.Mode()),
		ModTime: stat.ModTime(),
	}

	err = tarWriter.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("error writing tar header: %v", err)
	}

	bufPtr := bufPool.Get().(*[]byte)
	buf := *bufPtr
	_, err = io.CopyBuffer(tarWriter, file, buf)
	bufPool.Put(bufPtr)
	if err != nil {
		return fmt.Errorf("error copying file to tarball: %v", err)
	}

	return nil
}
