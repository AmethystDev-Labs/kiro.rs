import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getSettings, updateSettings } from '@/api/settings'
import type { UpdateSettingsRequest } from '@/types/api'

export function useSettings() {
  return useQuery({
    queryKey: ['settings'],
    queryFn: getSettings,
  })
}

export function useUpdateSettings() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (req: UpdateSettingsRequest) => updateSettings(req),
    onSuccess: (data) => {
      queryClient.setQueryData(['settings'], data)
    },
  })
}
