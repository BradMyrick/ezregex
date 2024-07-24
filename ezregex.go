package ezregex

import (
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
)

// LocalNameRegex is the regex pattern for validating local (ASCII) names
var LocalNameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// ValidateLocalName checks if the provided string is a valid local (ASCII) name
func ValidateLocalName(name string) bool {
    return LocalNameRegex.MatchString(name)
}

// UnicodeNameRegex is the regex pattern for validating Unicode names
var UnicodeNameRegex = regexp.MustCompile(`^\p{L}[\p{L}\p{N}_-]*$`)

// ValidateUnicodeName checks if the provided string is a valid Unicode name
func ValidateUnicodeName(name string) bool {
    return UnicodeNameRegex.MatchString(name)
}

// EmailRegex is the regex pattern for validating email addresses
var EmailRegex = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)

// ValidateEmail checks if the provided string is a valid email address
func ValidateEmail(email string) bool {
    return EmailRegex.MatchString(email)
}

// URLRegex is the regex pattern for validating URLs
var URLRegex = regexp.MustCompile(`^(https?:\/\/)?([a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5})(:[0-9]{1,5})?(\/.*)?$`)

// ValidateURL checks if the provided string is a valid URL
func ValidateURL(url string) bool {
    return URLRegex.MatchString(url)
}

// NumericRegex is the regex pattern for validating numeric input
var NumericRegex = regexp.MustCompile(`^\d+(?:\.\d+)?$`)

// ValidateNumeric checks if the provided string is a valid numeric value
func ValidateNumeric(input string) bool {
    return NumericRegex.MatchString(input)
}

// DateRegex is the regex pattern for validating dates in YYYY-MM-DD format
var DateRegex = regexp.MustCompile(`^(?:19|20)\d\d-(?:0[1-9]|1[0-2])-(?:0[1-9]|[0-9]|3)$`)

// ValidateDate checks if the provided string is a valid date in YYYY-MM-DD format
func ValidateDate(date string) bool {
    return DateRegex.MatchString(date)
}

// GraphQLNameRegex is the regex pattern for validating GraphQL names
var GraphQLNameRegex = regexp.MustCompile("^[_a-zA-Z][_a-zA-Z0-9]*$")

// ValidateGraphQLName checks if the provided string is a valid GraphQL name
func ValidateGraphQLName(name string) bool {
    return GraphQLNameRegex.MatchString(name)
}

// Base64Regex is the regex pattern for validating base64 encoded strings
var Base64Regex = regexp.MustCompile("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")

// ValidateBase64 checks if the provided string is a valid base64 encoded value
func ValidateBase64(input string) bool {
    return Base64Regex.MatchString(input)
}

// ValidateXML checks if the provided string is a valid XML document
func ValidateXML(xmlStr string) bool {
    return xml.Unmarshal([]byte(xmlStr), new(interface{})) == nil
}

// ValidateHTML checks if the provided string is a valid HTML document
func ValidateHTML(htmlStr string) bool {
    // Basic HTML tag validation
    htmlRegex := regexp.MustCompile(`<([a-z]+)([^<]+)*(?:>(.*)<\/\1>|\s+\/>)`)
    return htmlRegex.MatchString(htmlStr)
}

// ValidateCSV checks if the provided string is a valid CSV document
func ValidateCSV(csvStr string) bool {
    // Basic CSV validation: check for consistent number of fields per row
    rows := strings.Split(csvStr, "\n")
    if len(rows) < 2 {
        return false
    }
    numFields := len(strings.Split(rows[0], ","))
    for _, row := range rows[1:] {
        if len(strings.Split(row, ",")) != numFields {
            return false
        }
    }
    return true
}

// ValidateJSON checks if the provided string is a valid JSON document
func ValidateJSON(jsonStr string) bool {
    var js json.RawMessage
    return json.Unmarshal([]byte(jsonStr), &js) == nil
}

// ValidateFileExtension checks if the provided file name has an allowed extension
func ValidateFileExtension(fileName string, allowedExtensions []string) bool {
    fileExtension := strings.ToLower(fileName[strings.LastIndex(fileName, ".")+1:])
    for _, ext := range allowedExtensions {
        if fileExtension == strings.ToLower(ext) {
            return true
        }
    }
    return false
}

// ValidateFileSize checks if the provided file size is within the allowed limit
func ValidateFileSize(fileSize int64, maxSize int64) bool {
    return fileSize <= maxSize
}

// ValidateFileContent checks if the provided file content is safe and free from malicious content
func ValidateFileContent(fileContent []byte) bool {
    //TODO:  Implement file content validation logic here, such as virus scanning, content filtering, etc.
    return len(fileContent) > 0
}
