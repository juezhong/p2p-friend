package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func cleanExistingPath(base, input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return filepath.Abs(base)
	}
	var p string
	if filepath.IsAbs(input) {
		p = filepath.Clean(input)
	} else {
		p = filepath.Join(base, input)
	}
	p, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(p); err != nil {
		return "", err
	}
	return p, nil
}

func cleanTargetPath(base, input string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return filepath.Abs(base)
	}
	var p string
	if filepath.IsAbs(input) {
		p = filepath.Clean(input)
	} else {
		p = filepath.Join(base, input)
	}
	return filepath.Abs(p)
}

func changeDir(current, previous, arg string) (next, nextPrev string, err error) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return current, previous, errors.New("需要指定目录")
	}
	if arg == "-" {
		if previous == "" {
			return current, previous, errors.New("没有上一个目录")
		}
		return previous, current, nil
	}
	p, err := cleanExistingPath(current, arg)
	if err != nil {
		return current, previous, err
	}
	st, err := os.Stat(p)
	if err != nil {
		return current, previous, err
	}
	if !st.IsDir() {
		return current, previous, fmt.Errorf("not a directory: %s", arg)
	}
	return p, current, nil
}

func listPath(base, input string) (string, []remoteEntry, error) {
	p, err := cleanExistingPath(base, input)
	if err != nil {
		return "", nil, err
	}
	st, err := os.Stat(p)
	if err != nil {
		return "", nil, err
	}
	if !st.IsDir() {
		return p, []remoteEntry{{Name: filepath.Base(p), Dir: false, Size: st.Size(), Mode: uint32(st.Mode())}}, nil
	}
	items, err := os.ReadDir(p)
	if err != nil {
		return "", nil, err
	}
	entries := make([]remoteEntry, 0, len(items))
	for _, item := range items {
		info, err := item.Info()
		if err != nil {
			continue
		}
		entries = append(entries, remoteEntry{
			Name: item.Name(),
			Dir:  item.IsDir(),
			Size: info.Size(),
			Mode: uint32(info.Mode()),
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return p, entries, nil
}

func buildEntries(input string) ([]sendEntry, int64, bool, error) {
	abs, err := filepath.Abs(input)
	if err != nil {
		return nil, 0, false, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, 0, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, false, fmt.Errorf("不支持符号链接: %s", input)
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return nil, 0, false, fmt.Errorf("不支持的文件类型: %s", input)
	}

	rootParent := filepath.Dir(abs)
	var entries []sendEntry
	var total int64
	err = filepath.WalkDir(abs, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("不支持符号链接: %s", path)
		}
		if !fi.Mode().IsRegular() && !fi.IsDir() {
			return fmt.Errorf("不支持的文件类型: %s", path)
		}
		rel, err := filepath.Rel(rootParent, path)
		if err != nil {
			return err
		}
		entries = append(entries, sendEntry{
			FullPath: path,
			RelPath:  filepath.ToSlash(rel),
			Mode:     fi.Mode(),
			Size:     fi.Size(),
			IsDir:    fi.IsDir(),
		})
		if fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	if err != nil {
		return nil, 0, false, err
	}
	return entries, total, info.IsDir(), nil
}

func resolveReceiveRoot(base, requested, sourceName string) (string, error) {
	if strings.TrimSpace(requested) == "" {
		return filepath.Abs(filepath.Join(base, sourceName))
	}
	p, err := cleanTargetPath(base, requested)
	if err != nil {
		return "", err
	}
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return filepath.Join(p, sourceName), nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return p, nil
}

func transferEntryDestination(root, sourceName, wirePath string) (string, error) {
	wirePath = filepath.ToSlash(filepath.Clean(filepath.FromSlash(wirePath)))
	name := filepath.ToSlash(sourceName)
	var sub string
	switch {
	case wirePath == name:
		sub = ""
	case strings.HasPrefix(wirePath, name+"/"):
		sub = strings.TrimPrefix(wirePath, name+"/")
	default:
		return "", fmt.Errorf("entry path %q is outside transfer root %q", wirePath, name)
	}
	if sub == "" {
		return root, nil
	}
	localSub := filepath.FromSlash(sub)
	clean := filepath.Clean(localSub)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || filepath.IsAbs(clean) {
		return "", fmt.Errorf("unsafe transfer path: %q", wirePath)
	}
	p := filepath.Join(root, clean)
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absP, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(absRoot, absP)
	if err != nil {
		return "", err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("unsafe transfer path: %q", wirePath)
	}
	return absP, nil
}
