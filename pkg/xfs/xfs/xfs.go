package xfs

import (
	"bytes"
	"io"
	"io/fs"
	//"path"
	"path/filepath"
	"strings"
	"fmt"
	"time"
	"log"
    "sync"
    "golang.org/x/xerrors"
	"github.com/masahiro331/go-xfs-filesystem/xfs/utils"
)

const DEBUG = false



var (
	_ fs.FS        = &FileSystem{}
	_ fs.ReadDirFS = &FileSystem{}
	_ fs.StatFS    = &FileSystem{}

	_ fs.File     = &File{}
	_ fs.FileInfo = &FileInfo{}
	_ fs.DirEntry = dirEntry{}

	ErrOpenSymlink = xerrors.New("symlink open not support")
)

var (
	ErrReadSizeFormat   = "failed to read size error: actual(%d), expected(%d)"
	ErrSeekOffsetFormat = "failed to seek offset error: actual(%d), expected(%d)"
)



type MetadataCache struct {
    mu    sync.RWMutex
    cache map[string]interface{}
}

func NewMetadataCache() *MetadataCache {
    return &MetadataCache{
        cache: make(map[string]interface{}),
    }
}

func Logf(format string, args ...interface{}) {
	if DEBUG {
		log.Printf(format, args...)
	}
}

func (mc *MetadataCache) Get(key string) (interface{}, bool) {
    mc.mu.RLock()
    defer mc.mu.RUnlock()
    value, ok := mc.cache[key]
    return value, ok
}

func (mc *MetadataCache) Set(key string, value interface{}) {
    mc.mu.Lock()
    defer mc.mu.Unlock()
    mc.cache[key] = value
}

func (mc *MetadataCache) Delete(key string) {
    mc.mu.Lock()
    defer mc.mu.Unlock()
    delete(mc.cache, key)
}

// FileSystem is implemented io/fs FS interface
type FileSystem struct {
	r         *io.SectionReader
	PrimaryAG AG
	AGs       []AG
	cache Cache[string, any]
	metadataCache *MetadataCache
}

func Check(r io.Reader) bool {
	_, err := parseSuperBlock(r)
	if err != nil {
		return false
	}
	return true
}

func NewFS(r io.SectionReader, cache Cache[string, any]) (*FileSystem, error) {
	primaryAG, err := ParseAG(&r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse primary allocation group: %w", err)
	}

	if cache == nil {
		cache = &mockCache[string, any]{}
	}
	fileSystem := FileSystem{
		r:         &r,
		PrimaryAG: *primaryAG,
		AGs:       []AG{*primaryAG},
		cache:     cache,
		metadataCache: NewMetadataCache(),
	}

	AGSize := int64(primaryAG.SuperBlock.Agblocks) * int64(primaryAG.SuperBlock.BlockSize)
	for i := int64(1); i < int64(primaryAG.SuperBlock.Agcount); i++ {
		n, err := r.Seek(AGSize*i, 0)
		if err != nil {
			return nil, xerrors.Errorf("failed to seek file: %w", err)
		}
		if n != AGSize*i {
			return nil, xerrors.Errorf(ErrSeekOffsetFormat, n, AGSize*i)
		}
		ag, err := ParseAG(&r)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse allocation group %d: %w", i, err)
		}
		fileSystem.AGs = append(fileSystem.AGs, *ag)
	}
	return &fileSystem, nil
}

func (xfs *FileSystem) Close() error {
	return nil
}


func (xfs *FileSystem) Stat(name string) (fs.FileInfo, error) {
    const op = "stat"

    // Check the cache first
    if cachedInfo, ok := xfs.metadataCache.Get("stat:" + name); ok {
        return cachedInfo.(fs.FileInfo), nil
    }

    var info fs.FileInfo
    var err error

    if name == "/" {
        info, err = xfs.ReadDirInfo(name)
    } else {
        dirName, fileName := filepath.Split(name)
        dirInfo, err := xfs.ReadDirInfo(dirName)
        if err != nil {
            return nil, xfs.wrapError(op, name, err)
        }

        if dirInfo.IsDir() {
            entries, err := xfs.readDirEntry(dirName)
            if err != nil {
                return nil, xfs.wrapError(op, name, err)
            }
            for _, entry := range entries {
                if entry.Name() == fileName {
                    info, err = entry.Info()
                    break
                }
            }
        }
    }

    if err != nil {
        return nil, xfs.wrapError(op, name, err)
    }

    if info == nil {
        return nil, xfs.wrapError(op, name, fs.ErrNotExist)
    }

    xfs.metadataCache.Set("stat:"+name, info)

    return info, nil
}

func (xfs *FileSystem) newFile(dirEntry dirEntry) (*File, error) {
    if dirEntry.inode == nil {
        return nil, xerrors.New("nil inode")
    }

    Logf("Creating new file. Inode type: %v, Format: %v, Mode: %v, IsSymlink: %v, IsRegular: %v", 
        dirEntry.inode.inodeCore.Mode,
        dirEntry.inode.inodeCore.Format,
        dirEntry.inode.inodeCore.Mode,
        dirEntry.inode.inodeCore.IsSymlink(),
        dirEntry.inode.inodeCore.IsRegular())

    if dirEntry.inode.inodeCore.IsSymlink() {
        if dirEntry.inode.symlinkString != nil {
            Logf("Symlink target: %s", dirEntry.inode.symlinkString.Name)
            return &File{
                fs:           xfs,
                FileInfo:     dirEntry.FileInfo,
                buffer:       bytes.NewBufferString(dirEntry.inode.symlinkString.Name),
                blockSize:    int64(xfs.PrimaryAG.SuperBlock.BlockSize),
                currentBlock: -1,
                table:        nil,
            }, nil
        }
        Logf("Symlink with nil symlink string. Treating as regular file.")
    }

    if dirEntry.inode.inodeCore.Format == XFS_DINODE_FMT_LOCAL {
        Logf("Small file stored directly in inode")

        data := extractDataFromLocalInode(dirEntry.inode)
        return &File{
            fs:           xfs,
            FileInfo:     dirEntry.FileInfo,
            buffer:       bytes.NewBuffer(data),
            blockSize:    int64(xfs.PrimaryAG.SuperBlock.BlockSize),
            currentBlock: -1,
            table:        nil,
        }, nil
    }

    var recs []BmbtRec
    if dirEntry.inode.regularExtent != nil {
        recs = dirEntry.inode.regularExtent.bmbtRecs
    } else if dirEntry.inode.regularBtree != nil {
        recs = dirEntry.inode.regularBtree.bmbtRecs
    } else {
        Logf("Unsupported inode structure: %+v", dirEntry.inode)
        return &File{
            fs:           xfs,
            FileInfo:     dirEntry.FileInfo,
            buffer:       bytes.NewBuffer(nil),
            blockSize:    int64(xfs.PrimaryAG.SuperBlock.BlockSize),
            currentBlock: -1,
            table:        nil,
        }, nil
    }

    dt := make(dataTable)
    for _, rec := range recs {
        p := rec.Unpack()
        physicalBlockOffset := xfs.PrimaryAG.SuperBlock.BlockToPhysicalOffset(p.StartBlock)
        for i := int64(0); i < int64(p.BlockCount); i++ {
            dt[int64(p.StartOff)+i] = physicalBlockOffset + i
        }
    }

    return &File{
        fs:           xfs,
        FileInfo:     dirEntry.FileInfo,
        buffer:       bytes.NewBuffer(nil),
        blockSize:    int64(xfs.PrimaryAG.SuperBlock.BlockSize),
        currentBlock: -1,
        table:        dt,
    }, nil
}

func extractDataFromLocalInode(inode *Inode) []byte {
    return []byte{}
}


func (xfs *FileSystem) ReadDir(name string) ([]fs.DirEntry, error) {
	const op = "read directory"

    if cachedEntries, ok := xfs.metadataCache.Get("dir:" + name); ok {
        return cachedEntries.([]fs.DirEntry), nil
    }

	dirEntries, err := xfs.readDirEntry(name)
	if err != nil {
		return nil, xfs.wrapError(op, name, err)
	}

    xfs.metadataCache.Set("dir:"+name, dirEntries)

	return dirEntries, nil
}

func (xfs *FileSystem) ReadDirInfo(name string) (fs.FileInfo, error) {

    cacheKey := "dirinfo:" + name
    if cachedInfo, ok := xfs.metadataCache.Get(cacheKey); ok {
        return cachedInfo.(fs.FileInfo), nil
    }

    var info fs.FileInfo

    if name == "/" {
        inode, err := xfs.getRootInode()
        if err != nil {
            return nil, xerrors.Errorf("failed to parse root inode: %w", err)
        }
        info = FileInfo{
            name:  "/",
            inode: inode,
            mode:  fs.FileMode(inode.inodeCore.Mode),
        }
    } else {
        name = strings.TrimRight(name, string(filepath.Separator))
        dirs := strings.Split(name, string(filepath.Separator))
        currentInode := xfs.PrimaryAG.SuperBlock.Rootino

        for _, dir := range dirs {
            if dir == "" {
                continue
            }
            entries, err := xfs.listEntries(currentInode)
            if err != nil {
                return nil, xerrors.Errorf("failed to list entries: %w", err)
            }
            found := false
            for _, entry := range entries {
                if entry.Name() == dir {
                    inode, err := xfs.ParseInode(entry.InodeNumber())
                    if err != nil {
                        return nil, xerrors.Errorf("failed to parse inode: %w", err)
                    }
                    if !inode.inodeCore.IsDir() {
                        info = FileInfo{
                            name:  dir,
                            inode: inode,
                            mode:  fs.FileMode(inode.inodeCore.Mode),
                        }
                        found = true
                        break
                    }
                    currentInode = entry.InodeNumber()
                    found = true
                    break
                }
            }
            if !found {
                return nil, fs.ErrNotExist
            }
        }

        if info == nil {
            inode, err := xfs.ParseInode(currentInode)
            if err != nil {
                return nil, xerrors.Errorf("failed to parse inode: %w", err)
            }
            info = FileInfo{
                name:  filepath.Base(name),
                inode: inode,
                mode:  fs.FileMode(inode.inodeCore.Mode),
            }
        }
    }

    xfs.metadataCache.Set(cacheKey, info)

    return info, nil
}

func (xfs *FileSystem) getRootInode() (*Inode, error) {
	inode, err := xfs.ParseInode(xfs.PrimaryAG.SuperBlock.Rootino)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse root inode: %w", err)
	}
	return inode, nil
}

func (xfs *FileSystem) ReadFile(name string) ([]byte, error) {
    f, err := xfs.Open(name)
    if err != nil {
        return nil, err
    }
    defer f.Close()

    return io.ReadAll(f)
}
// TODO: support GlobFS Interface
func (xfs *FileSystem) Glob(pattern string) ([]string, error) {
	panic("implement me")
	return []string{}, nil
}

func (xfs *FileSystem) wrapError(op, path string, err error) error {
	return &fs.PathError{
		Op:   op,
		Path: path,
		Err:  err,
	}
}

func (xfs *FileSystem) Open(name string) (fs.File, error) {
    const op = "open"

    if !xfs.isValidPath(name) {
        return nil, xfs.wrapError(op, name, fs.ErrInvalid)
    }

    Logf("Opening file: %s", name)

    dirName, fileName := filepath.Split(name)
    dirEntries, err := xfs.ReadDir(dirName)
    if err != nil {
        Logf("Error reading directory %s: %v", dirName, err)
        return nil, xfs.wrapError(op, name, xerrors.Errorf("failed to read directory: %w", err))
    }

    var targetEntry dirEntry
    for _, entry := range dirEntries {
        Logf("Checking entry: %s (isDir: %v)", entry.Name(), entry.IsDir())
        if entry.Name() == fileName {
            if dir, ok := entry.(dirEntry); ok {
                targetEntry = dir
                break
            }
        }
    }

    if targetEntry.inode == nil {
        Logf("File not found: %s", name)
        return nil, fs.ErrNotExist
    }

    Logf("Creating new file for %s", name)
    f, err := xfs.newFile(targetEntry)
    if err != nil {
        Logf("Error creating new file for %s: %v", name, err)
		return &File{
            fs:           xfs,
            FileInfo:     targetEntry.FileInfo,
            buffer:       bytes.NewBuffer(nil),
            blockSize:    int64(xfs.PrimaryAG.SuperBlock.BlockSize),
            currentBlock: -1,
            table:        nil,
        }, nil		
    }


    return f, nil
}

func (xfs *FileSystem) seekInode(n uint64) (int64, error) {
	offset := int64(xfs.PrimaryAG.SuperBlock.InodeAbsOffset(n))
	off, err := xfs.r.Seek(offset, io.SeekStart)
	if err != nil {
		return 0, err
	}
	if off != offset {
		return 0, xerrors.Errorf(ErrSeekOffsetFormat, off, offset)
	}
	return off, nil
}

func (xfs *FileSystem) seekBlock(n int64) (int64, error) {
	offset := n * int64(xfs.PrimaryAG.SuperBlock.BlockSize)
	off, err := xfs.r.Seek(offset, io.SeekStart)
	if err != nil {
		return 0, err
	}
	if off != offset {
		return 0, xerrors.Errorf(ErrSeekOffsetFormat, off, offset)
	}
	return off, nil
}

func (xfs *FileSystem) readBlock(count uint32) ([]byte, error) {
	buf := make([]byte, 0, xfs.PrimaryAG.SuperBlock.BlockSize*count)
	for i := uint32(0); i < count; i++ {
		b, err := utils.ReadBlock(xfs.r)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	return buf, nil
}

func (xfs *FileSystem) readDirEntry(name string) ([]fs.DirEntry, error) {
	inode, err := xfs.getRootInode()
	if err != nil {
		return nil, xerrors.Errorf("failed to get root inode: %w", err)
	}

	fileInfos, err := xfs.listFileInfo(inode.inodeCore.Ino)
	if err != nil {
		return nil, xerrors.Errorf("failed to list root inode directory entries: %w", err)
	}

	currentInode := inode
	dirs := strings.Split(strings.Trim(filepath.Clean(name), string(filepath.Separator)), string(filepath.Separator))
	for i, dir := range dirs {
		found := false
		for _, fileInfo := range fileInfos {
			if fileInfo.Name() == dir {
				if !fileInfo.IsDir() {
					return nil, xerrors.Errorf("%s is file, directory: %w", fileInfo.Name(), fs.ErrNotExist)
				}
				found = true
				currentInode = fileInfo.inode
				break
			}
		}
		if !found && (dir != "" && dir != ".") {
			return nil, fs.ErrNotExist
		}

		fileInfos, err = xfs.listFileInfo(currentInode.inodeCore.Ino)
		if err != nil {
			return nil, xerrors.Errorf("failed to list directory entries inode: %d: %w", currentInode.inodeCore.Ino, err)
		}

		if i == len(dirs)-1 {
			var dirEntries []fs.DirEntry
			for _, fileInfo := range fileInfos {
				// Skip current directory and parent directory
				// infinit loop in walkDir
				if fileInfo.Name() == "." || fileInfo.Name() == ".." {
					continue
				}

				dirEntries = append(dirEntries, dirEntry{fileInfo})
			}
			return dirEntries, nil
		}
	}
	return nil, fs.ErrNotExist
}


func (xfs *FileSystem) listFileInfo(ino uint64) ([]FileInfo, error) {
    Logf("listFileInfo ----- ")

    cacheKey := fmt.Sprintf("fileinfo:%d", ino)
    if cachedInfos, ok := xfs.metadataCache.Get(cacheKey); ok {
        return cachedInfos.([]FileInfo), nil
    }

    entries, err := xfs.listEntries(ino)
    if err != nil {
        return nil, xerrors.Errorf("failed to list entries: %w", err)
    }

    var fileInfos []FileInfo
    for _, entry := range entries {
        inode, err := xfs.ParseInode(entry.InodeNumber())
        if err != nil {
            return nil, xerrors.Errorf("failed to parse inode %d: %w", entry.InodeNumber(), err)
        }
        // TODO: mode use inode.InodeCore.Mode
        fileInfos = append(fileInfos,
            FileInfo{
                name:  entry.Name(),
                inode: inode,
                mode:  fs.FileMode(inode.inodeCore.Mode),
            },
        )
    }

    xfs.metadataCache.Set(cacheKey, fileInfos)

    return fileInfos, nil
}

func (xfs *FileSystem) parseTree(bmbtRecs []BmbtRec) ([]Entry, error) {
	var entries []Entry
	for _, b := range bmbtRecs {
		p := b.Unpack()
		blockEntries, err := xfs.parseDir2Block(p)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse dir2 block: %w", err)
		}
		for _, entry := range blockEntries {
			entries = append(entries, entry)
		}
	}
	return entries, nil
}

func (xfs *FileSystem) listEntries(ino uint64) ([]Entry, error) {
	inode, err := xfs.ParseInode(ino)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse inode: %w", err)
	}

	if !inode.inodeCore.IsDir() {
		return nil, xerrors.New("error inode is not directory")
	}

	var entries []Entry
	if inode.directoryLocal != nil {
		for _, entry := range inode.directoryLocal.entries {
			entries = append(entries, entry)
		}
	} else if inode.directoryExtents != nil {
		if len(inode.directoryExtents.bmbtRecs) == 0 {
			return nil, xerrors.New("directory extents tree bmbtRecs is empty error")
		}
		entries, err = xfs.parseTree(inode.directoryExtents.bmbtRecs)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse extents tree: %w", err)
		}
	} else if inode.directoryBtree != nil {
		if len(inode.directoryBtree.bmbtRecs) == 0 {
			return nil, xerrors.New("directory extents btree bmbtRecs is empty error")
		}
		entries, err = xfs.parseTree(inode.directoryBtree.bmbtRecs)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse btree: %w", err)
		}

	} else {
		return nil, xerrors.New("not found entries")
	}

	return entries, nil
}

// FileInfo is implemented io/fs FileInfo interface
type FileInfo struct {
	name  string
	inode *Inode

	mode fs.FileMode
}

func (i FileInfo) IsDir() bool {
	return i.inode.inodeCore.IsDir()
}

func (i FileInfo) ModTime() time.Time {
	return time.Unix(int64(i.inode.inodeCore.Mtime), 0)
}

func (i FileInfo) Size() int64 {
	return int64(i.inode.inodeCore.Size)
}

func (i FileInfo) Name() string {
	return i.name
}

func (i FileInfo) Sys() interface{} {
	return nil
}

func (i FileInfo) Mode() fs.FileMode {
	return i.mode
}

// dirEntry is implemented io/fs DirEntry interface
type dirEntry struct {
	FileInfo
}

func (d dirEntry) Type() fs.FileMode {
	return d.FileInfo.Mode().Type()
}

func (d dirEntry) Info() (fs.FileInfo, error) { return d.FileInfo, nil }

// File is implemented io/fs File interface
type File struct {
	fs *FileSystem
	FileInfo

	buffer *bytes.Buffer

	blockSize    int64
	currentBlock int64
	table        dataTable
}

// map[offset]
type dataTable map[int64]int64

func (f *File) Stat() (fs.FileInfo, error) {
	return &f.FileInfo, nil
}

func (f *File) Read(buf []byte) (int, error) {
	if f.buffer == nil {
		return 0, io.EOF
	}
	if f.buffer.Len() == 0 {
		f.currentBlock++
		if f.currentBlock*f.blockSize >= f.Size() {
			f.buffer = nil
			return 0, io.EOF
		}
	} else {
		return f.buffer.Read(buf)
	}

	offset, ok := f.table[f.currentBlock]
	if !ok {
		if f.Size()-f.blockSize*f.currentBlock < f.blockSize {
			f.buffer.Write(make([]byte, f.Size()-f.blockSize*f.currentBlock))
		}
		f.buffer.Write(make([]byte, f.blockSize))
	} else {
		_, err := f.fs.seekBlock(offset)
		if err != nil {
			return 0, xerrors.Errorf("failed to seek block: %w", err)
		}
		b, err := f.fs.readBlock(1)
		if err != nil {
			return 0, xerrors.Errorf("failed to read block: %w", err)
		}

		if f.Size()-f.blockSize*f.currentBlock < f.blockSize {
			b = b[:f.Size()-f.blockSize*f.currentBlock]
		}
		n, err := f.buffer.Write(b)
		if n != len(b) {
			return 0, xerrors.Errorf("write buffer error: actual(%d), expected(%d)", n, len(b))
		}
	}

	return f.buffer.Read(buf)
}

func (f *File) Close() error {
	return nil
}


func (xfs *FileSystem) isValidPath(name string) bool {
    if !strings.HasPrefix(name, "/") {
        return false
    }
    
    parts := strings.Split(name, "/")
    for _, part := range parts {
        if part == ".." {
            return false
        }
    }
    
    return true
}