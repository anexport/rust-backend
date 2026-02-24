'use client';

import { useEffect, useState } from 'react';
import { Input } from '@/components/ui/input';

type SearchInputProps = {
  value?: string;
  placeholder?: string;
  delayMs?: number;
  onSearch: (value: string) => void;
};

export function SearchInput({
  value = '',
  placeholder = 'Search...',
  delayMs = 300,
  onSearch,
}: SearchInputProps) {
  const [local, setLocal] = useState(value);

  useEffect(() => {
    setLocal(value);
  }, [value]);

  useEffect(() => {
    const id = setTimeout(() => onSearch(local.trim()), delayMs);
    return () => clearTimeout(id);
  }, [local, delayMs, onSearch]);

  return (
    <Input
      value={local}
      onChange={(e) => setLocal(e.target.value)}
      placeholder={placeholder}
      className="max-w-md"
    />
  );
}
