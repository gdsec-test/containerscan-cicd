package test

import (
	"archive/tar"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func getGoldenImageURI(imageTag string) string {
	return fmt.Sprintf("%s/%s:%s", GOLDEN_AMI_REPO, SCANNER_IMAGE, imageTag)
}

func encode(v interface{}) string {
	encodedJSON, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(encodedJSON)
}

func tarCompressFile(tarPath, filePath string) {
	tarFile, err := os.Create(tarPath)
	if err != nil {
		log.Fatal(err)
	}
	defer tarFile.Close()

	tw := tar.NewWriter(tarFile)
	defer tw.Close()

	file, err := ioutil.ReadFile(filePath)
	if err != nil {
		log.Fatal(err)
	}

	hdr := &tar.Header{
		Name: filePath,
		Mode: 0600,
		Size: int64(len(file)),
	}

	if err := tw.WriteHeader(hdr); err != nil {
		log.Fatal(err)
	}

	if _, err := tw.Write(file); err != nil {
		log.Fatal(err)
	}
}

func tarCompressDirectory(tarPath, dirPath string) {
	tarFile, err := os.Create(tarPath)
	if err != nil {
		log.Fatal(err)
	}
	defer tarFile.Close()

	tw := tar.NewWriter(tarFile)
	defer tw.Close()

	filepath.Walk(dirPath, func(file string, fi os.FileInfo, err error) error {
		hdr, err := tar.FileInfoHeader(fi, file)
		if err != nil {
			return nil
		}

		hdr.Name = strings.ReplaceAll(file, dirPath, "")

		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		// if not a dir, write file content
		if !fi.IsDir() {
			data, err := os.Open(file)
			if err != nil {
				return err
			}
			if _, err := io.Copy(tw, data); err != nil {
				return err
			}
		}
		return nil
	})
}
