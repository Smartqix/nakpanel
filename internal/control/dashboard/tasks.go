package dashboard

import "context"

type activeJobReader interface {
	CountActiveJobs(context.Context) (int, error)
}

func JobActive(state string) bool {
	switch state {
	case "available", "scheduled", "running", "retryable", "pending":
		return true
	default:
		return false
	}
}

func ActiveJobs(jobs []Job) int {
	count := 0
	for _, job := range jobs {
		if JobActive(job.State) {
			count++
		}
	}
	return count
}
