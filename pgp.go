package utils

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/jinzhu/gorm"
	"github.com/qor/validations"
	"golang.org/x/crypto/openpgp"
)

const (
	PGP_FILE_SUFFIX = ".gpg"
)

type GpgPublicKey struct {
	gorm.Model
	Name string
	Key  string `sql:"type:text"`
}

func (pk *GpgPublicKey) Validate(db *gorm.DB) {

	if pk.Name == "" {
		db.AddError(validations.NewError(pk, "Name", "Name can't be blank"))
	}
	if pk.Key == "" {
		db.AddError(validations.NewError(pk, "Key", "Key can't be blank"))
	} else {
		_, err := ReadPublicKey(pk.Key)
		if err != nil {
			db.AddError(validations.NewError(pk, "Key", "wrong key"))
		}
	}

}

func ReadPublicKey(publicKey string) (openpgp.EntityList, error) {
	buf := bytes.NewBufferString(publicKey)
	e, err := openpgp.ReadArmoredKeyRing(buf)
	if err != nil {
		return nil, fmt.Errorf("reading error", err)
	}
	return e, nil
}

func EncryptFile(publicKeys []string, plainTextFile string, cipherTextFile string) (err error) {

	var recipients openpgp.EntityList
	for _, pk := range publicKeys {
		if recipient, err := ReadPublicKey(pk); err != nil {
			continue
		} else {
			recipients = append(recipients, recipient...)
		}
	}

	var plainTextInput *os.File
	if plainTextInput, err = os.Open(plainTextFile); err != nil {
		return err
	}
	defer plainTextInput.Close()

	inputStat, err := plainTextInput.Stat()
	if err != nil {
		return err
	}
	plainTextBytes := inputStat.Size()

	var cipherTextOutput *os.File
	if cipherTextOutput, err = os.Create(cipherTextFile); err != nil {
		return err
	}

	fHints := &openpgp.FileHints{
		IsBinary: false,
		FileName: path.Base(plainTextFile),
		ModTime:  inputStat.ModTime(),
	}

	var we io.WriteCloser
	if we, err = openpgp.Encrypt(cipherTextOutput, recipients, nil, fHints, nil); err != nil {
		return err
	}
	defer we.Close()

	copiedBytes, err := io.Copy(we, plainTextInput)
	if copiedBytes != plainTextBytes {
		return fmt.Errorf("encrypted only %d bytes out of %d", copiedBytes, plainTextBytes)
	}
	return nil
}
