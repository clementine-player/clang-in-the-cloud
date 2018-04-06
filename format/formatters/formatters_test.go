package formatters

import (
	"io/ioutil"
	"testing"

	"sourcegraph.com/sourcegraph/go-diff/diff"

	. "github.com/smartystreets/goconvey/convey"
)

func TestAdditions(t *testing.T) {
	Convey("", t, func() {
		data, err := ioutil.ReadFile("6011.patch")
		So(err, ShouldBeNil)
		diffs, err := diff.ParseMultiFileDiff(data)
		So(err, ShouldBeNil)
		So(diffs, ShouldHaveLength, 2)

		hunks := diffs[0].Hunks

		So(hasAdditions(hunks[0]), ShouldBeTrue)
		So(hasAdditions(hunks[1]), ShouldBeTrue)
		So(hasAdditions(hunks[2]), ShouldBeTrue)

		additions := findAdditions(hunks[0])
		So(additions, ShouldHaveLength, 1)
		So(additions[0].Start, ShouldEqual, 3)
		So(additions[0].End, ShouldEqual, 3)
	})
}
