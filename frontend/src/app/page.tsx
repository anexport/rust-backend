import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

export default function Home() {
  return (
    <main className="container mx-auto py-10 px-4 md:px-6 max-w-7xl">
      <div className="flex flex-col items-center justify-center space-y-4 text-center">
        <div className="space-y-2">
          <h1 className="text-3xl font-bold tracking-tighter sm:text-4xl md:text-5xl lg:text-6xl/none">
            Welcome to the Marketplace
          </h1>
          <p className="mx-auto max-w-[700px] text-gray-500 md:text-xl dark:text-gray-400">
            Rent, list, and connect. The best platform for discovering and sharing equipment.
          </p>
        </div>
        <div className="space-x-4">
          <Button asChild>
            <Link href="/equipment">Browse Equipment</Link>
          </Button>
        </div>
      </div>
      
      <div className="mx-auto grid max-w-7xl items-center gap-6 py-12 lg:grid-cols-2 lg:gap-12">
        <Card>
          <CardHeader>
            <CardTitle>List Equipment</CardTitle>
            <CardDescription>
              Got gear you don&apos;t use every day? List it and earn extra income.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="outline" asChild>
              <Link href="/equipment/new">Create Listing</Link>
            </Button>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Chat & Connect</CardTitle>
            <CardDescription>
              Discuss terms directly with owners through our real-time messaging platform.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Button variant="outline" asChild>
              <Link href="/messages">View Messages</Link>
            </Button>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
