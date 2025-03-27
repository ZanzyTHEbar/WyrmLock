package ipc

import (
	"wyrmlock/internal/monitor"
)

// MessageType defines the type of message being sent over IPC
type MessageType string

const (
	// Message types for IPC
	MsgProcessEvent     MessageType = "process_event"
	MsgAuthRequest      MessageType = "auth_request"
	MsgAuthResponse     MessageType = "auth_response"
	MsgTerminateProcess MessageType = "terminate_process"
	MsgResumeProcess    MessageType = "resume_process"
	MsgShutdown         MessageType = "shutdown"
	MsgPing             MessageType = "ping"
	MsgPong             MessageType = "pong"
	MsgList             MessageType = "list"
	MsgListResponse     MessageType = "list_response"
	MsgUnlock           MessageType = "unlock"
	MsgUnlockResponse   MessageType = "unlock_response"
	MsgStatusRequest    MessageType = "status_request"
	MsgStatusResponse   MessageType = "status_response"
	MsgShutdownAck      MessageType = "shutdown_ack"
)

// Message is the structure used for IPC between daemon and client
type Message struct {
	Type          MessageType            `json:"type"`
	Process       *monitor.ProcessInfo   `json:"process,omitempty"`
	AppName       string                 `json:"app_name,omitempty"`
	PID           int                    `json:"pid,omitempty"`
	Password      string                 `json:"password,omitempty"`
	Success       bool                   `json:"success,omitempty"`
	Error         string                 `json:"error,omitempty"`
	Data          map[string]interface{} `json:"data,omitempty"`
	ProcessList   []monitor.ProcessInfo  `json:"process_list,omitempty"`
	ProtectedApps []string               `json:"protected_apps,omitempty"`
	Version       string                 `json:"version,omitempty"`
}
