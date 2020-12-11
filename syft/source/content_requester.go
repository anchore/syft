package source

import "sync"

type ContentRequester struct {
	request map[Location][]*FileData
	lock    sync.Mutex
}

func NewContentRequester(data ...*FileData) *ContentRequester {
	requester := &ContentRequester{
		request: make(map[Location][]*FileData),
	}
	for _, d := range data {
		requester.Add(d)
	}
	return requester
}

func (b *ContentRequester) Add(data *FileData) {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.request[data.Location] = append(b.request[data.Location], data)
}

func (b *ContentRequester) Execute(resolver ContentResolver) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	var locations = make([]Location, len(b.request))
	idx := 0
	for l := range b.request {
		locations[idx] = l
		idx++
	}

	response, err := resolver.MultipleFileContentsByLocation(locations)
	if err != nil {
		return err
	}

	for l, contents := range response {
		for i := range b.request[l] {
			b.request[l][i].Contents = contents
		}
	}
	return nil
}
