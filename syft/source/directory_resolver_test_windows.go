package source

// only run this test on Windows
func Test_windowsToPosix(t *testing.T) {
	tests := []struct {
		windowsPath   string
		expectedPosix string
	}{
		{
			windowsPath:   `C:\some\\windows\\Place`,
			expectedPosix: "/c/some/windows/Place",
		},
	}
	for _, test := range tests {
		t.Run(test.windowsPath, func(t *testing.T) {
			posixPath := windowsToPosix(test.windowsPath)
			assert.Equal(t, test.expectedPosix, posixPath)
		})
	}
}
