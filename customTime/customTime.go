/*
This package is an extension of the time package
*/
package customTime

import (
	"regexp"
	"strconv"
	"time"
)

// time.ParseDuration doesn't support (d)ays or (y)ears - This is an extension to support those
func ParseDuration(s string) (time.Duration, error) {
	var totalDuration time.Duration
	re := regexp.MustCompile(`(\d+)([ywdhms])`)
	matches := re.FindAllStringSubmatch(s, -1)

	for _, match := range matches {
		value, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, err
		}
		unit := match[2]

		switch unit {
		case "y":
			totalDuration += time.Hour * 24 * 365 * time.Duration(value)
		case "d":
			totalDuration += time.Hour * 24 * time.Duration(value)
		case "h":
			totalDuration += time.Hour * time.Duration(value)
		case "m":
			totalDuration += time.Minute * time.Duration(value)
		case "s":
			totalDuration += time.Second * time.Duration(value)
		}
	}

	return totalDuration, nil
}
