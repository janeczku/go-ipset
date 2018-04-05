/*
Copyright 2015 Jan Broer All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package ipset is a library providing a wrapper to the IPtables ipset userspace utility
package ipset

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-semver/semver"
)

const minIpsetVersion = "6.0.0"

var (
	ipsetPath            string
	errIpsetNotFound     = errors.New("Ipset utility not found")
	errIpsetNotSupported = errors.New("Ipset utility version is not supported, requiring version >= 6.0")
)

// Params defines optional parameters for creating a new set.
type Params struct {
	HashFamily string
	HashSize   int
	MaxElem    int
	Timeout    int
	Exist      bool
}

// IPSet implements an Interface to an set.
type IPSet struct {
	Name       string
	HashType   string
	HashFamily string
	HashSize   int
	MaxElem    int
	Timeout    int
}

func init() {
	path, err := exec.LookPath("ipset")
	if err != nil {
		panic(errIpsetNotFound)
	}
	ipsetPath = path
	supportedVersion, err := getIpsetSupportedVersion()
	if err != nil {
		log.Warnf("Error checking ipset version, assuming version at least 6.0.0: %v", err)
		supportedVersion = true
	}
	if supportedVersion {
		return
	}
	panic(errIpsetNotSupported)
}

func (s *IPSet) createHashSet(name string, exist bool) error {
	/*	out, err := exec.Command("/usr/bin/sudo",
		ipsetPath, "create", name, s.HashType, "family", s.HashFamily, "hashsize", strconv.Itoa(s.HashSize),
		"maxelem", strconv.Itoa(s.MaxElem), "timeout", strconv.Itoa(s.Timeout), "-exist").CombinedOutput()*/

	cmd := []string{
		ipsetPath, "create", name, s.HashType, "family", s.HashFamily, "hashsize", strconv.Itoa(s.HashSize),
		"maxelem", strconv.Itoa(s.MaxElem), "timeout", strconv.Itoa(s.Timeout),
	}

	if exist {
		cmd = append(cmd, "-exist")
	}

	out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error creating ipset %s with type %s: %v (%s)", name, s.HashType, err, out)
	}
	out, err = exec.Command(ipsetPath, "flush", name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error flushing ipset %s: %v (%s)", name, err, out)
	}
	return nil
}

// New creates a new set and returns an Interface to it.
// Example:
// 	testIpset := ipset.New("test", "hash:ip", &ipset.Params{})
func New(name string, hashtype string, p *Params) (*IPSet, error) {
	// Using the ipset utilities default values here
	if p.HashSize == 0 {
		p.HashSize = 1024
	}

	if p.MaxElem == 0 {
		p.MaxElem = 65536
	}

	if p.HashFamily == "" {
		p.HashFamily = "inet"
	}

	// Check if hashtype is a type of hash
	if !strings.HasPrefix(hashtype, "hash:") {
		return nil, fmt.Errorf("not a hash type: %s", hashtype)
	}

	s := IPSet{name, hashtype, p.HashFamily, p.HashSize, p.MaxElem, p.Timeout}
	err := s.createHashSet(name, p.Exist)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Names is used to show names of all lists
func Names() ([]string, error) {
	out, err := exec.Command(ipsetPath, "-n", "list").CombinedOutput()
	if err != nil {
		return []string{}, fmt.Errorf("error listing names: %v (%s)", err, out)
	}
	return strings.Split(string(out), "\n"), nil
}

// List is used to show the contents of a set
func List(listName string) ([]string, error) {
	out, err := exec.Command(ipsetPath, "list", listName).CombinedOutput()
	if err != nil {
		return []string{}, fmt.Errorf("error listing set %s: %v (%s)", listName, err, out)
	}
	r := regexp.MustCompile("(?m)^(.*\n)*Members:\n")
	list := r.ReplaceAllString(string(out[:]), "")
	return strings.Split(list, "\n"), nil
}

// Destroy is used to destroy the set.
func Destroy(listName string) error {
	out, err := exec.Command(ipsetPath, "destroy", listName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error destroying set %s: %v (%s)", listName, err, out)
	}
	return nil
}

// Refresh is used to to overwrite the set with the specified entries.
// The ipset is updated on the fly by hot swapping it with a temporary set.
func (s *IPSet) Refresh(entries []string) error {
	tempName := s.Name + "-temp"
	err := s.createHashSet(tempName, true)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		out, err := exec.Command(ipsetPath, "add", tempName, entry, "-exist").CombinedOutput()
		if err != nil {
			log.Errorf("error adding entry %s to set %s: %v (%s)", entry, tempName, err, out)
		}
	}
	err = Swap(tempName, s.Name)
	if err != nil {
		return err
	}
	err = destroyIPSet(tempName)
	if err != nil {
		return err
	}
	return nil
}

// Test is used to check whether the specified entry is in the set or not.
func Test(listName, entry string) (bool, error) {
	out, err := exec.Command(ipsetPath, "test", listName, entry).CombinedOutput()
	if err == nil {
		reg, e := regexp.Compile("NOT")
		if e == nil && reg.MatchString(string(out)) {
			return false, nil
		} else if e == nil {
			return true, nil
		} else {
			return false, fmt.Errorf("error testing entry %s: %v", entry, e)
		}
	} else {
		return false, fmt.Errorf("error testing entry %s: %v (%s)", entry, err, out)
	}
}
func (s *IPSet) Test(entry string) (bool, error) {
	return Test(s.Name, entry)
}

// Add is used to add the specified entry to the set.
// A timeout of 0 means that the entry will be stored permanently in the set.
func Add(listName, entry string, timeout int) error {
	out, err := exec.Command(ipsetPath, "add", listName, entry, "timeout", strconv.Itoa(timeout), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error adding entry %s: %v (%s)", entry, err, out)
	}
	return nil
}
func (s *IPSet) Add(entry string, timeout int) error {
	return Add(s.Name, entry, timeout)
}

// AddOption is used to add the specified entry to the set.
// A timeout of 0 means that the entry will be stored permanently in the set.
func (s *IPSet) AddOption(entry string, option string, timeout int) error {
	out, err := exec.Command(ipsetPath, "add", s.Name, entry, option, "timeout", strconv.Itoa(timeout), "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error adding entry %s with option %s : %v (%s)", entry, option, err, out)
	}
	return nil
}

// Del is used to delete the specified entry from the set.
func Del(listName, entry string) error {
	out, err := exec.Command(ipsetPath, "del", listName, entry, "-exist").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error deleting entry %s: %v (%s)", entry, err, out)
	}
	return nil
}
func (s *IPSet) Del(entry string) error {
	return Del(s.Name, entry)
}

// Flush is used to flush all entries in the set.
func (s *IPSet) Flush() error {
	out, err := exec.Command(ipsetPath, "flush", s.Name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("error flushing set %s: %v (%s)", s.Name, err, out)
	}
	return nil
}

// List is used to show the contents of a set
func (s *IPSet) List() ([]string, error) {
	return List(s.Name)
}

// Destroy is used to destroy the set.
func (s *IPSet) Destroy() error {
	return Destroy(s.Name)
}

// DestroyAll is used to destroy the set.
func DestroyAll() error {
	out, err := exec.Command(ipsetPath, "destroy").CombinedOutput()
	if err != nil {
		return fmt.Errorf("error destroying set %s (%s)", err, out)
	}
	return nil
}

// Swap is used to hot swap two sets on-the-fly. Use with names of existing sets of the same type.
func Swap(from, to string) error {
	out, err := exec.Command(ipsetPath, "swap", from, to).Output()
	if err != nil {
		return fmt.Errorf("error swapping ipset %s to %s: %v (%s)", from, to, err, out)
	}
	return nil
}

func destroyIPSet(name string) error {
	out, err := exec.Command(ipsetPath, "destroy", name).Output()
	if err != nil {
		return fmt.Errorf("error destroying ipset %s: %v (%s)", name, err, out)
	}
	return nil
}

func destroyAll() error {
	out, err := exec.Command(ipsetPath, "destroy").Output()
	if err != nil {
		return fmt.Errorf("error destroying all ipsetz %s (%s)", err, out)
	}
	return nil
}

func getIpsetSupportedVersion() (bool, error) {
	minVersion, err := semver.NewVersion(minIpsetVersion)
	if err != nil {
		return false, err
	}
	// Returns "vX.Y".
	vstring, err := getIpsetVersionString()
	if err != nil {
		return false, err
	}
	// Make a dotted-tri format version string
	vstring = vstring + ".0"
	// Make a semver of the part after the v in "vX.X.X".
	version, err := semver.NewVersion(vstring[1:])
	if err != nil {
		return false, err
	}
	if version.LessThan(*minVersion) {
		return false, nil
	}
	return true, nil
}

func getIpsetVersionString() (string, error) {
	bytes, err := exec.Command(ipsetPath, "--version").CombinedOutput()
	if err != nil {
		return "", err
	}
	versionMatcher := regexp.MustCompile("v[0-9]+\\.[0-9]+")
	match := versionMatcher.FindStringSubmatch(string(bytes))
	if match == nil {
		return "", fmt.Errorf("no ipset version found in string: %s", bytes)
	}
	return match[0], nil
}
