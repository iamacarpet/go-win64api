//go:build windows && amd64
// +build windows,amd64

package winapi

import (
	"fmt"
	"time"

	"github.com/google/cabbie/search"
	"github.com/google/cabbie/session"
	"github.com/google/cabbie/updatehistory"
	"github.com/scjalliance/comshim"

	so "github.com/iamacarpet/shared"
)

var updateResultStatus []string = []string{
	"Completed", // Was "Pending", swap to "Completed" to match Update UI in OS
	"Completed", // Was "In Progress", swap to "Completed" to match Update UI in OS
	"Completed",
	"Completed With Errors",
	"Failed",
	"Aborted",
}

func UpdatesPending() (*so.WindowsUpdate, error) {
	retData := &so.WindowsUpdate{}

	comshim.Add(1)
	defer comshim.Done()

	reqUpdates, _, err := listUpdates(false)
	if err != nil {
		return nil, fmt.Errorf("Error getting Windows Update info: %s", err.Error())
	}
	retData.NumUpdates = len(reqUpdates)

	for _, u := range reqUpdates {
		retData.UpdateHistory = append(retData.UpdateHistory, &so.WindowsUpdateHistory{
			EventDate:  time.Now(),
			Status:     "In Progress",
			UpdateName: u,
		})
	}

	history, err := updateHistory()
	if err != nil {
		return nil, fmt.Errorf("Error getting update history: %s", err.Error())
	}

	for _, e := range history.Entries {
		retData.UpdateHistory = append(retData.UpdateHistory, &so.WindowsUpdateHistory{
			EventDate:  e.Date,
			Status:     updateResultStatus[int(e.ResultCode)],
			UpdateName: e.Title,
		})
	}

	if retData.NumUpdates > 0 {
		retData.UpdatesReq = true
	}

	return retData, nil
}

func listUpdates(hidden bool) ([]string, []string, error) {
	// Set search criteria
	c := search.BasicSearch + " OR Type='Driver' OR " + search.BasicSearch + " AND Type='Software'"
	if hidden {
		c += " and IsHidden=1"
	} else {
		c += " and IsHidden=0"
	}

	// Start Windows update session
	s, err := session.New()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new Windows Update session: %v", err)
	}
	defer s.Close()

	q, err := search.NewSearcher(s, c, []string{}, 1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create a new searcher object: %v", err)
	}
	defer q.Close()

	uc, err := q.QueryUpdates()
	if err != nil {
		return nil, nil, fmt.Errorf("error encountered when attempting to query for updates: %v", err)
	}
	defer uc.Close()

	var reqUpdates, optUpdates []string
	for _, u := range uc.Updates {
		// Add to optional updates list if the update does not match the required categories.
		if !u.InCategories([]string{"Critical Updates", "Definition Updates", "Security Updates"}) {
			optUpdates = append(optUpdates, u.Title)
			continue
		}
		// Skip virus updates as they always exist.
		if !u.InCategories([]string{"Definition Updates"}) {
			reqUpdates = append(reqUpdates, u.Title)
		}
	}
	return reqUpdates, optUpdates, nil
}

func updateHistory() (*updatehistory.History, error) {
	// Start Windows update session
	s, err := session.New()
	if err != nil {
		return nil, err
	}
	defer s.Close()

	// Create Update searcher interface
	searcher, err := search.NewSearcher(s, "", []string{}, 1)
	if err != nil {
		return nil, err
	}
	defer searcher.Close()

	return updatehistory.Get(searcher)
}
