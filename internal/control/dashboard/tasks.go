package dashboard

import "context"

// Tasks contains a bounded recent list and a separate count over all visible jobs.
type Tasks struct {
	Active int
	Items  []Job
}

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

func (s *Store) GetTasks(ctx context.Context) (Tasks, error) {
	result := Tasks{Items: []Job{}}
	if s.jobs == nil {
		return result, nil
	}
	jobs, err := s.jobs.ListRecentJobs(ctx, 8)
	if err != nil {
		return result, err
	}
	result.Items = jobs
	result.Active = ActiveJobs(jobs)
	if counter, ok := s.jobs.(activeJobReader); ok {
		result.Active, err = counter.CountActiveJobs(ctx)
	}
	return result, err
}
