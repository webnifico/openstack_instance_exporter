package main

var labelsInstanceBase = []string{"domain", "server_name", "instance_uuid", "project_uuid", "project_name", "user_uuid"}

func labelsInstance(extra ...string) []string {
	out := make([]string, 0, len(labelsInstanceBase)+len(extra))
	out = append(out, labelsInstanceBase...)
	out = append(out, extra...)
	return out
}
