echo 'Please run the script as root'
git clone https://github.com/Ne0nd0g/merlin-agent-dll
cd merlin-agent-dll
go build -buildmode=c-archive main.go
gcc -shared -pthread -o merlin.dll merlin.c main.a -lwinmm -lntdll -lws2_32
