module example.com/repro

go 1.23

require rsc.io/quote v1.5.1

require (
	golang.org/x/text v0.0.0-20170915032832-14c0d48ead0c // indirect
	rsc.io/sampler v1.3.0 // indirect
)

replace (
	rsc.io/quote => rsc.io/quote v1.5.2
	rsc.io/sampler => rsc.io/sampler v1.3.1
)
