package source

import "sync"

// ContentRequester is an object tailored for taking source.Location objects which file contents will be resolved
// upon invoking Execute().
type ContentRequester struct {
	request map[Location][]*FileData
	lock    sync.Mutex
}

// NewContentRequester creates a new ContentRequester object with the given initial request data.
func NewContentRequester(data ...*FileData) *ContentRequester {
	requester := &ContentRequester{
		request: make(map[Location][]*FileData),
	}
	for _, d := range data {
		requester.Add(d)
	}
	return requester
}

// Add appends a new single FileData containing a source.Location to later have the contents fetched and stored within
// the given FileData object.
func (r *ContentRequester) Add(data *FileData) {
	r.lock.Lock()
	defer r.lock.Unlock()

	r.request[data.Location] = append(r.request[data.Location], data)
}

// Execute takes the previously provided source.Location's and resolves the file contents, storing the results within
// the previously provided FileData objects.
func (r *ContentRequester) Execute(resolver ContentResolver) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	var locations = make([]Location, len(r.request))
	idx := 0
	for l := range r.request {
		locations[idx] = l
		idx++
	}

	response, err := resolver.MultipleFileContentsByLocation(locations)
	if err != nil {
		return err
	}

	for l, contents := range response {
		for i := range r.request[l] {
			r.request[l][i].Contents = contents
		}
	}
	return nil
}
