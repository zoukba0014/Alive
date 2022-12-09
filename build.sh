env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ./release/Alive_darwin_amd64
env CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -trimpath -ldflags "-s -w" -o ./release/Alive_linux_386
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ./release/Alive_linux_amd64_upx
env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ./release/Alive_linux_amd64
env CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -trimpath -ldflags "-s -w" -o ./release/Alive_linux_arm
env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o ./release/Alive_linux_arm64
env CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -trimpath -ldflags "-s -w" -o ./release/Alive_windows_386.exe
env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ./release/Alive_windows_amd64_upx.exe
env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o ./release/Alive_windows_amd64.exe
env CGO_ENABLED=0 GOOS=linux GOARCH=mips64 go build -trimpath -ldflags "-s -w" -o ./release/Alive_linux_mips64
env CGO_ENABLED=0 GOOS=linux GOARCH=mips64le go build -trimpath -ldflags "-s -w" -o ./release/Alive_linux_mips64le
env CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go build -trimpath -ldflags "-s -w" -o ./release/Alive_linux_mips
env CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath -ldflags "-s -w" -o ./release/Alive_linux_mipsle


upx -9 ./release/Alive_linux_amd64_upx
upx -9 ./release/Alive_windows_amd64_upx.exe