package depscan

import "os"

func readFile(name string) ([]byte, error) { return os.ReadFile(name) }
