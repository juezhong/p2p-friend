package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func buildEntries(input string) ([]sendEntry, int64, error) {
	abs, err := filepath.Abs(input)
	if err != nil {
		return nil, 0, err
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, fmt.Errorf("不支持符号链接: %s", input)
	}
	if !info.Mode().IsRegular() && !info.IsDir() {
		return nil, 0, fmt.Errorf("不支持的文件类型: %s", input)
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
		rel = filepath.ToSlash(rel)
		entries = append(entries, sendEntry{
			FullPath: path,
			RelPath:  rel,
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
		return nil, 0, err
	}
	return entries, total, nil
}

func sendSessionWriter(bw *bufio.Writer, entries []sendEntry, total int64, prefix string) error {
	p := &progress{Start: time.Now(), LastPrint: time.Now(), Total: total, Prefix: prefix}
	buf := make([]byte, copyBufferSize)

	for _, e := range entries {
		if e.IsDir {
			if err := writeRecordHeader(bw, recordDir, e.RelPath, uint32(e.Mode.Perm()), 0); err != nil {
				return err
			}
			continue
		}

		if err := writeRecordHeader(bw, recordFile, e.RelPath, uint32(e.Mode.Perm()), uint64(e.Size)); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}

		f, err := os.Open(e.FullPath)
		if err != nil {
			return fmt.Errorf("open %s: %w", e.FullPath, err)
		}
		h := sha256.New()
		p.Current = e.RelPath
		p.CurrentDone = 0
		p.CurrentSize = e.Size
		if err := copyExactWithProgress(bw, f, h, e.Size, buf, p); err != nil {
			f.Close()
			return fmt.Errorf("send %s: %w", e.RelPath, err)
		}
		if err := f.Close(); err != nil {
			return err
		}
		if _, err := bw.Write(h.Sum(nil)); err != nil {
			return err
		}
		if err := bw.Flush(); err != nil {
			return err
		}
	}

	if err := bw.WriteByte(recordEnd); err != nil {
		return err
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	p.print(true)
	return nil
}

func writeRecordHeader(w *bufio.Writer, typ byte, path string, mode uint32, size uint64) error {
	pathBytes := []byte(path)
	if len(pathBytes) == 0 || len(pathBytes) > maxPathBytes {
		return fmt.Errorf("invalid path length for %q", path)
	}
	if err := w.WriteByte(typ); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(pathBytes))); err != nil {
		return err
	}
	if _, err := w.Write(pathBytes); err != nil {
		return err
	}
	if err := binary.Write(w, binary.BigEndian, mode); err != nil {
		return err
	}
	if typ == recordFile {
		if err := binary.Write(w, binary.BigEndian, size); err != nil {
			return err
		}
	}
	return nil
}
