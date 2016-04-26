package winapi

import (
    "fmt"

    ole "github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

func UpdatesPending() (bool, int, error) {
    ole.CoInitialize(0)
    defer ole.CoUninitialize()
    unknown, err := oleutil.CreateObject("Microsoft.Update.Session")
    if err != nil {
        return false, 0, fmt.Errorf("Unable to create initial object, %s", err.Error())
    }
    defer unknown.Release()
    update, err := unknown.QueryInterface(ole.IID_IDispatch)
    if err != nil {
        return false, 0, fmt.Errorf("Unable to create query interface, %s", err.Error())
    }
    defer update.Release()
    oleutil.PutProperty(update, "ClientApplicationID", "GoLang Windows API")

    us, err := oleutil.CallMethod(update, "CreateUpdateSearcher")
    if err != nil {
        return false, 0, fmt.Errorf("Error creating update searcher, %s", err.Error())
    }
    usd := us.ToIDispatch()
    defer usd.Release()

    usr, err := oleutil.CallMethod(usd, "Search", "IsInstalled=0 and Type='Software' and IsHidden=0")
    if err != nil {
        return false, 0, fmt.Errorf("Error performing update search, %s", err.Error())
    }
    usrd := usr.ToIDispatch()
    defer usrd.Release()

    upd, err := oleutil.GetProperty(usrd, "Updates")
    if err != nil {
        return false, 0, fmt.Errorf("Error getting Updates collection, %s", err.Error())
    }
    updd := upd.ToIDispatch()
    defer updd.Release()

    updn, err := oleutil.GetProperty(updd, "Count")
    if err != nil {
        return false, 0, fmt.Errorf("Error getting update count, %s", err.Error())
    }
    updnn := int(updn.Val)

    pending := false
    if updnn > 0 {
        pending = true
    }
    return pending, updnn, nil
}
