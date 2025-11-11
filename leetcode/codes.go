package leetcode

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
