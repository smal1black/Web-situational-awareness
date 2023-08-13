package filedelet

import (
	"os"
)

func DeleteFile(filePath string) error {
	err := os.Remove(filePath)
	if err != nil {
		return err
	}
	return nil
}
func RemoveSpaces(data []byte) []byte {

	result := make([]byte, 0, len(data))

	for _, b := range data {
		if b != ' ' {
			result = append(result, b)
		}
	}

	return result
}
