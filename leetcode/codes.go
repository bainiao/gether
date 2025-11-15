package leetcode

import "sort"

func LongestIncreasingSubsequence(arr []int) int {
	res := make([]int, len(arr))
	maxl := 1
	for i := 0; i < len(arr); i++ {
		res[i] = 1
		for j := i - 1; j >= 0; j-- {
			if arr[j] < arr[i] {
				if res[j]+1 > res[i] {
					res[i] = res[j] + 1
					maxl = res[i]
				}
			}
		}
	}
	return maxl
}
func ThreeSum(nums []int) [][]int {
	sort.Ints(nums)
	var res [][]int
	for i := 0; i < len(nums)-1 && nums[i] <= 0; i++ {
		for j := len(nums) - 1; j > 1 && nums[j] >= 0; j-- {
			for k := i + 1; k < j; k++ {
				if nums[i]+nums[j]+nums[k] == 0 {
					res = append(res, []int{nums[i], nums[k], nums[j]})
					break
				}
			}
		}
	}
	return res
}
