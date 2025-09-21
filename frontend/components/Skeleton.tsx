import { ComponentPropsWithoutRef } from 'react';
import clsx from 'clsx';

export type SkeletonProps = ComponentPropsWithoutRef<'div'>;

export function Skeleton({ className, 'aria-hidden': ariaHidden = true, ...props }: SkeletonProps) {
  return <div {...props} aria-hidden={ariaHidden} className={clsx('skeleton-base', className)} />;
}
