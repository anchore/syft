package source

type Locations []Location

func (l Locations) Len() int {
	return len(l)
}

func (l Locations) Less(i, j int) bool {
	if l[i].RealPath == l[j].RealPath {
		if l[i].VirtualPath == l[j].VirtualPath {
			return l[i].FileSystemID < l[j].FileSystemID
		}
		return l[i].VirtualPath < l[j].VirtualPath
	}
	return l[i].RealPath < l[j].RealPath
}

func (l Locations) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}
