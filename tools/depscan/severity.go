package depscan

// severity ranks the severity strings of both pnpm (lower case) and Trivy
// (upper case); each scanner has its own table and anything outside it is
// unknown, which blocks.
type severity int

const (
	sevInfo severity = iota
	sevLow
	sevModerate
	sevHigh
	sevCritical
)

// threshold is the lowest severity that blocks.
const threshold = sevHigh

var pnpmSeverity = map[string]severity{
	"info": sevInfo, "low": sevLow, "moderate": sevModerate, "high": sevHigh, "critical": sevCritical,
}

var trivySeverity = map[string]severity{
	"UNKNOWN": sevInfo, "LOW": sevLow, "MEDIUM": sevModerate, "HIGH": sevHigh, "CRITICAL": sevCritical,
}
