'use client'

import { useState } from 'react'
import { useTranslations } from 'next-intl'
import { Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  onConfirm: () => Promise<void>
}

export function CloseSessionDialog({ open, onOpenChange, onConfirm }: Props) {
  const t = useTranslations('Query')
  const [closing, setClosing] = useState(false)

  const handleConfirm = async () => {
    setClosing(true)
    try {
      await onConfirm()
      onOpenChange(false)
    } finally {
      setClosing(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t('session.closeTitle')}</DialogTitle>
          <DialogDescription>{t('session.closeDescription')}</DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={closing}>
            {t('session.keep')}
          </Button>
          <Button variant="destructive" onClick={handleConfirm} disabled={closing}>
            {closing && <Loader2 className="size-3.5 animate-spin" />}
            {t('session.close')}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
