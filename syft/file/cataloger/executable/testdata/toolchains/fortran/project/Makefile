BIN=../bin

all: $(BIN)/hello_fortran

$(BIN)/hello_fortran: hello.f90
	gfortran hello.f90 -o $(BIN)/hello_fortran

clean:
	rm -f $(BIN)/hello_fortran
