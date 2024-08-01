package xfssource

import (
    "context"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sync"
    "github.com/anchore/syft/syft/artifact"
    syftFile "github.com/anchore/syft/syft/file"
    "github.com/anchore/syft/syft/source"
    stereoFile "github.com/anchore/stereoscope/pkg/file"
    "github.com/masahiro331/go-xfs-filesystem/xfs"
	"github.com/anchore/syft/internal/log"
    "strings"
    "bytes"
    "encoding/binary"
)

type xfsSource struct {
    id       artifact.ID
    path     string
    resolver *xfsResolver
    mutex    *sync.Mutex
    xfsFS    *xfs.FileSystem
    file     *os.File  
}

type SimpleCache struct {
	mu    sync.Mutex
	cache map[string]any
}

func (c *SimpleCache) Add(key string, value any) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, found := c.cache[key]; !found {
		c.cache[key] = value
		return true
	}
	return false
}

func (c *SimpleCache) Get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, found := c.cache[key]
	return value, found
}

func NewSimpleCache() *SimpleCache {
	return &SimpleCache{
		cache: make(map[string]any),
	}
}


func New(path string) (*xfsSource, error) {
    log.Debug("attempting to create XFS source for path: %s", path)

    f, err := os.Open(path)
    if err != nil {
        log.Debug("unable to open XFS image file: %w", err)
        return nil, fmt.Errorf("unable to open XFS image file: %w", err)
    }

    offset, err := findXFSPartitionOffset(f)
    if err != nil {
        f.Close()
        return nil, fmt.Errorf("failed to find XFS partition: %w", err)
    }

    log.Debugf("XFS partition found at offset: %d", offset)

    fileInfo, err := f.Stat()
    if err != nil {
        f.Close()
        return nil, fmt.Errorf("unable to get file info: %w", err)
    }

    sectionReader := io.NewSectionReader(f, offset, fileInfo.Size()-offset)
    cache := NewSimpleCache()

    filesystem, err := xfs.NewFS(*sectionReader, cache)
    if err != nil {
        f.Close()
        return nil, fmt.Errorf("failed to create XFS filesystem: %w", err)
    }

    log.Debugf("XFS filesystem created successfully")

    id := artifact.ID(path)

    source := &xfsSource{
        id:    id,
        path:  path,
        mutex: &sync.Mutex{},
        xfsFS: filesystem,
        file:  f,
    }

    resolver := newXFSResolver(filesystem, source)
    source.resolver = resolver

    return source, nil
}


func (s *xfsSource) ID() artifact.ID {
    return s.id
}

func (s *xfsSource) Describe() source.Description {
    return source.Description{
        ID:       string(s.id),
        Name:     filepath.Base(s.path),
        Version:  "",
        Metadata: source.XFSMetadata{
            Path: s.path,
        },
    }
}

func (s *xfsSource) FileResolver(_ source.Scope) (syftFile.Resolver, error) {
    return s.resolver, nil
}

func (s *xfsSource) Close() error {
    if s.file != nil {
        return s.file.Close()
    }
    return nil
}

type xfsResolver struct {
    fs *xfs.FileSystem
    source *xfsSource 
}

func newXFSResolver(fs *xfs.FileSystem, source *xfsSource) *xfsResolver {
    return &xfsResolver{
        fs:     fs,
        source: source,
    }
}

func (r *xfsResolver) FileContentsByLocation(location syftFile.Location) (io.ReadCloser, error) {
    log.Debugf("FileContentsByLocation called for: %s", location.RealPath)
    
    f, err := r.fs.Open(location.RealPath)
    if err != nil {
        log.Debugf("Error opening file %s: %v", location.RealPath, err)
        return nil, fmt.Errorf("error opening file %s: %w", location.RealPath, err)
    }
    defer f.Close()

    content, err := io.ReadAll(f)
    if err != nil {
        log.Debugf("Error reading file %s: %v", location.RealPath, err)
        return nil, fmt.Errorf("error reading file %s: %w", location.RealPath, err)
    }

    if len(content) == 0 {
        log.Debugf("Warning: Empty content for file %s", location.RealPath)
    }

    log.Debugf("Successfully read file %s (size: %d bytes)", location.RealPath, len(content))


    if len(content) < 100 {
        log.Debugf("File content of %s: %q", location.RealPath, string(content))
    }

    if strings.Contains(location.RealPath, "swap") {
        log.Debugf("Swap-related file found: %s", location.RealPath)
        previewSize := 100
        if len(content) < previewSize {
            previewSize = len(content)
        }
        log.Debugf("First %d bytes of swap file content: %q", previewSize, string(content[:previewSize]))
        
        switch location.RealPath {
        case "/proc/swaps":
            logSwapInfo(content)
        case "/etc/fstab":
            logFstabSwapEntries(content)
        }
    }

    return io.NopCloser(bytes.NewReader(content)), nil
}

func logSwapInfo(content []byte) {
    lines := bytes.Split(content, []byte("\n"))
    if len(lines) > 1 {
        log.Debugf("/proc/swaps header: %q", string(lines[0]))
        log.Debugf("Number of swap entries: %d", len(lines)-1) 
    }
}

func logFstabSwapEntries(content []byte) {
    lines := bytes.Split(content, []byte("\n"))
    for _, line := range lines {
        if bytes.Contains(line, []byte("swap")) {
            log.Debugf("fstab swap entry: %q", string(line))
        }
    }
}

func (r *xfsResolver) FileMetadataByLocation(location syftFile.Location) (stereoFile.Metadata, error) {
    info, err := r.fs.Stat(location.RealPath)
    if err != nil {
        return stereoFile.Metadata{}, err
    }
    return NewMetadata(info), nil
}

func (r *xfsResolver) HasPath(path string) bool {
    _, err := r.fs.Stat(path)
    return err == nil
}


func (r *xfsResolver) FilesByPath(paths ...string) ([]syftFile.Location, error) {
    log.Debugf("FilesByPath called with paths: %v", paths)
    var locations []syftFile.Location
    for _, path := range paths {
        info, err := r.fs.Stat(path)
        if err != nil {
            log.Debugf("Error stating file %s: %v", path, err)
            continue
        }
        if info == nil {
            log.Debugf("Unexpected nil FileInfo for path %s", path)
            continue
        }
        if !info.IsDir() {
            locations = append(locations, syftFile.NewLocation(path))
            log.Debugf("Found file: %s", path)
            
            switch path {
            case "/var/lib/rpm/Packages":
                log.Debugf("Found RPM database file")
            case "/var/lib/dpkg/status":
                log.Debugf("Found DPKG status file")
            case "/var/lib/pacman/local":
                log.Debugf("Found Pacman database directory")
            case "/usr/lib/opkg/status":
                log.Debugf("Found OPKG status file")
            }
        }
    }
    return locations, nil
}


func (r *xfsResolver) FilesByGlob(patterns ...string) ([]syftFile.Location, error) {
    log.Debugf("FilesByGlob called with patterns: %v", patterns)
    uniquePaths := make(map[string]bool)
    var uniqueLocations []syftFile.Location

    for _, pattern := range patterns {
        log.Debugf("Processing pattern: %s", pattern)
        err := r.walkXFSFS("/", func(path string, isDir bool) error {
            if isDir {
                return nil
            }

            matched, err := r.matchGlob(pattern, path)
            if err != nil {
                log.Debugf("Error matching pattern %s for path %s: %v", pattern, path, err)
                return nil 
            }
            if !matched {
                return nil
            }

            if uniquePaths[path] {
                return nil
            }

            log.Debugf("Matched file: %s", path)
            location := syftFile.NewLocation(path)
            uniquePaths[path] = true
            uniqueLocations = append(uniqueLocations, location)

            return nil
        })
        if err != nil {
            log.Debugf("Error walking filesystem for pattern %s: %v", pattern, err)
        }
    }

    log.Debugf("FilesByGlob found %d locations", len(uniqueLocations))
    return uniqueLocations, nil
}

func (r *xfsResolver) matchGlob(pattern, path string) (bool, error) {
    patternParts := strings.Split(pattern, "/")
    pathParts := strings.Split(path, "/")

    return r.matchGlobParts(patternParts, pathParts)
}

func (r *xfsResolver) matchGlobParts(pattern, path []string) (bool, error) {
    for i, patternPart := range pattern {
        if i >= len(path) {
            return false, nil
        }

        switch patternPart {
        case "*":
            continue
        case "**":
            for j := i; j <= len(path); j++ {
                if matched, _ := r.matchGlobParts(pattern[i+1:], path[j:]); matched {
                    return true, nil
                }
            }
            return false, nil
        default:
            matched, err := filepath.Match(patternPart, path[i])
            if err != nil {
                return false, err
            }
            if !matched {
                return false, nil
            }
        }
    }

    return len(pattern) == len(path), nil
}


func (r *xfsResolver) FilesByMIMEType(types ...string) ([]syftFile.Location, error) {
    log.Debugf("FilesByMIMEType called with types: %v", types)

    var locations []syftFile.Location
    uniquePaths := make(map[string]bool)

    err := r.walkXFSFS("/", func(path string, isDir bool) error {
        if isDir {
            return nil
        }
        
        f, err := r.fs.Open(path)
        if err != nil {
            log.Debugf("Error opening file %s: %v", path, err)
            return nil
        }
        defer f.Close()

        header := make([]byte, 264)
        n, err := io.ReadFull(f, header)
        if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
            log.Debugf("Error reading file header %s: %v", path, err)
            return nil
        }
        header = header[:n]

        log.Debugf("Read %d bytes from file %s", n, path)

        mimeType := detectFileMIMEType(header)
        log.Debugf("File: %s, Detected MIME type: %s", path, mimeType)
        
        for _, t := range types {
            if mimeType == t && !uniquePaths[path] {
                log.Debugf("Matched MIME type %s for file %s", t, path)
                locations = append(locations, syftFile.NewLocation(path))
                uniquePaths[path] = true
                break
            }
        }
        return nil
    })

    if err != nil {
        log.Debugf("Error walking filesystem for MIME types: %v", err)
    }

    log.Debugf("FilesByMIMEType found %d locations", len(locations))
    return locations, err
}



func detectFileMIMEType(header []byte) string {
    if len(header) < 4 {
        return "application/octet-stream"
    }

    if bytes.HasPrefix(header, []byte{0x7F, 'E', 'L', 'F'}) {
        if len(header) >= 5 {
            switch header[4] {
            case 1:
                return "application/x-executable" 
            case 2:
                if len(header) >= 16 && header[16] == 3 {
                    return "application/x-sharedlib" 
                }
                return "application/x-executable" 
            }
        }
        return "application/x-elf" 
    }

    if len(header) >= 0x3C+4 && bytes.Equal(header[0x3C:0x3C+4], []byte("PE\x00\x00")) {
        return "application/vnd.microsoft.portable-executable"
    }

    if len(header) >= 4 {
        machHeader := binary.LittleEndian.Uint32(header)
        if machHeader == 0xfeedface || machHeader == 0xfeedfacf || 
           machHeader == 0xcefaedfe || machHeader == 0xcffaedfe {  
            return "application/x-mach-binary"
        }
    }

    switch {
    case bytes.HasPrefix(header, []byte{0x1F, 0x8B, 0x08}):
        return "application/gzip"
    case bytes.HasPrefix(header, []byte("PK\x03\x04")):
        return "application/zip"
    case bytes.HasPrefix(header, []byte("Rar!\x1A\x07\x00")):
        return "application/x-rar-compressed"
    case bytes.HasPrefix(header, []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}):
        return "application/x-xz"
    }

    return "application/octet-stream"
}

func (r *xfsResolver) RelativeFileByPath(location syftFile.Location, path string) *syftFile.Location {
    absPath := filepath.Clean(filepath.Join(filepath.Dir(location.RealPath), path))

    if shouldSkipPath(absPath) {
        log.Debugf("Skipping problematic path: %s", absPath)
        return nil
    }

    info, err := r.fs.Stat(absPath)
    if err != nil {
        log.Debugf("Error accessing file %s: %v", absPath, err)
        return nil
    }

    if info.IsDir() {
        log.Debugf("Skipping directory: %s", absPath)
        return nil
    }

    if !strings.HasPrefix(absPath, "/") {
        log.Debugf("Path is outside of XFS filesystem: %s", absPath)
        return nil
    }

    newLocation := syftFile.NewVirtualLocation(absPath, absPath)
    return &newLocation
}

func (r *xfsResolver) AllLocations(ctx context.Context) <-chan syftFile.Location {
    ch := make(chan syftFile.Location)
    go func() {
        defer close(ch)
        log.Debug("Starting AllLocations for XFS source")

        err := r.walkXFSFS("/", func(path string, isDir bool) error {
            select {
            case <-ctx.Done():
                return ctx.Err()
            default:
                if !isDir {
                    ch <- syftFile.NewLocation(path)
                }
                return nil
            }
        })
        if err != nil {
            log.Debugf("Error in AllLocations: %v", err)
        }
    }()
    return ch
}

func (r *xfsResolver) walkXFSFS(path string, fn func(path string, isDir bool) error) error {
    if shouldSkipPath(path) {
        return nil
    }

    entries, err := r.fs.ReadDir(path)
    if err != nil {
        log.Debugf("Failed to read directory %s: %v", path, err)
        return nil 
    }

    for _, entry := range entries {
        fullPath := filepath.Join(path, entry.Name())
        
        if shouldSkipPath(fullPath) {
            continue
        }

        isDir := entry.IsDir()
        if err := fn(fullPath, isDir); err != nil {
            if err == filepath.SkipDir {
                continue
            }
            return err
        }

        if isDir {
            if err := r.walkXFSFS(fullPath, fn); err != nil {
                if err == filepath.SkipDir {
                    continue
                }
                return err
            }
        }
    }

    return nil
}

func isXFSImage(path string) bool {
    f, err := os.Open(path)
    if err != nil {
        return false
    }
    defer f.Close()

    offset, err := findXFSPartitionOffset(f)
    if err != nil {
        return false
    }

    _, err = f.Seek(offset, io.SeekStart)
    if err != nil {
        return false
    }

    return xfs.Check(f)
}



func NewMetadata(info os.FileInfo) stereoFile.Metadata {
    var fileType stereoFile.Type
    var linkDestination string

    switch {
    case info.IsDir():
        fileType = stereoFile.TypeDirectory
    case info.Mode()&os.ModeSymlink != 0:
        fileType = stereoFile.TypeSymLink
    default:
        fileType = stereoFile.TypeRegular
    }

    return stereoFile.Metadata{
        FileInfo:        info,
        Path:            info.Name(),
        LinkDestination: linkDestination,
        UserID:          -1, 
        GroupID:         -1, 
        Type:            fileType,
        MIMEType:        "", 
    }
}


func shouldSkipPath(path string) bool {
    problematicPaths := []string{"/dev", "/proc", "/sys","/var/lib/docker/"}
    for _, pp := range problematicPaths {
        if strings.HasPrefix(path, pp) {
            return true
        }
    }
    return false
}

const (
    GPTHeaderSize     = 92
    GPTSignature      = "EFI PART"
    XFSPartitionGUID  = "AF3DC60F-8384-7247-8E79-3D69D8477DE4"
    SectorSize        = 512
)

func findXFSPartitionOffset(file *os.File) (int64, error) {
    log.Debugf("Attempting to find XFS partition offset")

    gptHeader := make([]byte, GPTHeaderSize)
    _, err := file.ReadAt(gptHeader, SectorSize)
    if err != nil {
        log.Debugf("Failed to read GPT header: %v", err)
        return 0, fmt.Errorf("failed to read GPT header: %w", err)
    }

    if string(gptHeader[:8]) != GPTSignature {
        log.Debugf("Invalid GPT signature: %s", string(gptHeader[:8]))
        return 0, fmt.Errorf("invalid GPT signature")
    }

    partitionEntrySize := binary.LittleEndian.Uint32(gptHeader[84:88])
    partitionEntryCount := binary.LittleEndian.Uint32(gptHeader[80:84])
    log.Debugf("Partition entry size: %d, count: %d", partitionEntrySize, partitionEntryCount)

    partitionEntriesStart := binary.LittleEndian.Uint64(gptHeader[72:80]) * SectorSize
    partitionEntriesSize := int64(partitionEntrySize * partitionEntryCount)
    partitionEntries := make([]byte, partitionEntriesSize)
    _, err = file.ReadAt(partitionEntries, int64(partitionEntriesStart))
    if err != nil {
        log.Debugf("Failed to read partition entries: %v", err)
        return 0, fmt.Errorf("failed to read partition entries: %w", err)
    }

    xfsGUID := convertGUIDToBytes(XFSPartitionGUID)
    for i := uint32(0); i < partitionEntryCount; i++ {
        entryStart := i * partitionEntrySize
        partitionTypeGUID := partitionEntries[entryStart : entryStart+16]
        if bytes.Equal(partitionTypeGUID, xfsGUID) {
            firstLBA := binary.LittleEndian.Uint64(partitionEntries[entryStart+32 : entryStart+40])
            offset := int64(firstLBA * SectorSize)
            log.Debugf("XFS partition found at offset: %d (Partition %d)", offset, i+1)
            return offset, nil
        }
    }

    log.Debugf("No XFS partition found in GPT, checking common offsets")
    commonOffsets := []int64{0, 512, 4096, 1048576, 2097152, 11534336} 
    for _, offset := range commonOffsets {
        isXFS, err := checkXFSSignature(file, offset)
        if err != nil {
            log.Debugf("Error checking XFS signature at offset %d: %v", offset, err)
            continue
        }
        if isXFS {
            log.Debugf("XFS signature found at offset: %d", offset)
            return offset, nil
        }
    }

    return 0, fmt.Errorf("XFS partition not found")
}

func checkXFSSignature(file *os.File, offset int64) (bool, error) {
    _, err := file.Seek(offset, io.SeekStart)
    if err != nil {
        return false, err
    }

    header := make([]byte, 4)
    _, err = io.ReadFull(file, header)
    if err != nil {
        return false, err
    }

    isXFS := binary.BigEndian.Uint32(header) == 0x58465342
    log.Debugf("XFS signature check at offset %d: %v", offset, isXFS)
    return isXFS, nil
}

func convertGUIDToBytes(guid string) []byte {
    guid = guid[:8] + guid[9:13] + guid[14:18] + guid[19:23] + guid[24:]
    guidBytes := make([]byte, 16)
    for i := 0; i < 16; i++ {
        b, _ := binary.ReadUvarint(bytes.NewBufferString(guid[i*2 : i*2+2]))
        guidBytes[i] = byte(b)
    }
    for i, j := 0, 3; i < j; i, j = i+1, j-1 {
        guidBytes[i], guidBytes[j] = guidBytes[j], guidBytes[i]
    }
    for i, j := 4, 5; i < j; i, j = i+1, j-1 {
        guidBytes[i], guidBytes[j] = guidBytes[j], guidBytes[i]
    }
    for i, j := 6, 7; i < j; i, j = i+1, j-1 {
        guidBytes[i], guidBytes[j] = guidBytes[j], guidBytes[i]
    }
    return guidBytes
}

