/*
This package contains functions for date and time manipulation
*/
package dataAndTime

import (
	"strconv"
	"time"
)

// GetYear returns the current year
func GetYear() string {
	year, _, _ := time.Now().Date()
	return strconv.Itoa(year)
}
