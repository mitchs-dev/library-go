package customTime

import (
	"regexp"
	"strconv"
	"time"
)

// time.ParseDuration doesn't support (d)ays, (M)onths or (y)ears - This is an extension to support those
func ParseDuration(s string) (time.Duration, error) {
	startTime := time.Now()
	re := regexp.MustCompile(`(\d+)([yMwdhms])`)
	matches := re.FindAllStringSubmatch(s, -1)

	for _, match := range matches {
		value, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, err
		}
		unit := match[2]

		switch unit {
		case "y":
			startTime = startTime.AddDate(value, 0, 0)
		case "M":
			startTime = startTime.AddDate(0, value, 0)
		case "w":
			startTime = startTime.AddDate(0, 0, 7*value)
		case "d":
			startTime = startTime.AddDate(0, 0, value)
		case "h":
			startTime = startTime.Add(time.Hour * time.Duration(value))
		case "m":
			startTime = startTime.Add(time.Minute * time.Duration(value))
		case "s":
			startTime = startTime.Add(time.Second * time.Duration(value))
		}
	}

	return time.Until(startTime), nil
}
