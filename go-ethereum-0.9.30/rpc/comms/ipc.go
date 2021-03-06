package comms

import (
	"github.com/ethereum/go-ethereum/rpc/api"
	"github.com/ethereum/go-ethereum/rpc/codec"
)

type IpcConfig struct {
	Endpoint string
}

type ipcClient struct {
	c codec.ApiCoder
}

func (self *ipcClient) Close() {
	self.c.Close()
}

func (self *ipcClient) Send(req interface{}) error {
	return self.c.WriteResponse(req)
}

func (self *ipcClient) Recv() (interface{}, error) {
	return self.c.ReadResponse()
}

// Create a new IPC client, UNIX domain socket on posix, named pipe on Windows
func NewIpcClient(cfg IpcConfig, codec codec.Codec) (*ipcClient, error) {
	return newIpcClient(cfg, codec)
}

// Start IPC server
func StartIpc(cfg IpcConfig, codec codec.Codec, apis ...api.EthereumApi) error {
	offeredApi := api.Merge(apis...)
	return startIpc(cfg, codec, offeredApi)
}
