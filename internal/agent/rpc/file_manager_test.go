package rpc

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/nakroteck/nakpanel/internal/types"
)

type fakeRPCFileManager struct{ username string }

func (f *fakeRPCFileManager) ListFiles(_ context.Context, req types.FileListReq) (types.FileListResult, error) {
	f.username = req.Username
	return types.FileListResult{Total: 2}, nil
}
func (f *fakeRPCFileManager) SearchFiles(context.Context, types.FileSearchReq) (types.FileSearchResult, error) {
	return types.FileSearchResult{}, nil
}
func (f *fakeRPCFileManager) ReadFile(context.Context, types.FileReadReq) (types.FileReadResult, error) {
	return types.FileReadResult{}, nil
}
func (f *fakeRPCFileManager) WriteFile(context.Context, types.FileWriteReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeRPCFileManager) CreateEntry(context.Context, types.FileCreateReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeRPCFileManager) CopyFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeRPCFileManager) MoveFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeRPCFileManager) DeleteFiles(context.Context, types.FileBatchReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeRPCFileManager) ArchiveFiles(context.Context, types.FileArchiveReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeRPCFileManager) ExtractArchive(context.Context, types.FileExtractReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeRPCFileManager) SetFileMode(context.Context, types.FileModeReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeRPCFileManager) ImportTransfer(context.Context, types.FileTransferImportReq) (types.FileMutationResult, error) {
	return types.FileMutationResult{}, nil
}
func (f *fakeRPCFileManager) ExportTransfer(context.Context, types.FileTransferExportReq) (types.FileTransferResult, error) {
	return types.FileTransferResult{}, nil
}

func TestDispatchListFilesUsesTypedFileManager(t *testing.T) {
	files := &fakeRPCFileManager{}
	dispatcher := NewDispatcher(&fakeReloader{}, Options{FileManager: files})
	response := dispatcher.Dispatch(context.Background(), types.Request{Op: types.OpListFiles, ID: "files-1", Data: json.RawMessage(`{"username":"npdemo","path":"","page":1,"per_page":100,"sort":"name","order":"asc"}`)})
	if !response.OK || files.username != "npdemo" {
		t.Fatalf("response=%#v username=%q", response, files.username)
	}
	var result types.FileListResult
	if err := json.Unmarshal(response.Data, &result); err != nil || result.Total != 2 {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestDispatchFileManagerRejectsUnknownFields(t *testing.T) {
	dispatcher := NewDispatcher(&fakeReloader{}, Options{FileManager: &fakeRPCFileManager{}})
	response := dispatcher.Dispatch(context.Background(), types.Request{Op: types.OpListFiles, ID: "files-2", Data: json.RawMessage(`{"username":"npdemo","absolute_path":"/etc"}`)})
	if response.OK {
		t.Fatalf("unknown field accepted: %#v", response)
	}
}
