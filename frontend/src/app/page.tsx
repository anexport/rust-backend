import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import Link from 'next/link';
import { fetchServer } from '@/lib/server';
import { Search, MapPin, Zap, Shield } from 'lucide-react';

export const dynamic = 'force-dynamic';

interface EquipmentItem {
  id: string;
  title: string;
  description: string;
  daily_rate: number;
  photos: { photo_url: string }[];
}

export default async function Home() {
  // Fetch featured items
  const equipmentRes = await fetchServer('/api/equipment?limit=6');
  const rawEquipmentData = equipmentRes.ok ? await equipmentRes.json() : {};
  const featuredItems: EquipmentItem[] = Array.isArray(rawEquipmentData.items) 
    ? rawEquipmentData.items.slice(0, 6) 
    : [];

  return (
    <div className="flex flex-col min-h-screen">
      {/* Hero Section */}
      <section className="relative w-full py-20 md:py-32 overflow-hidden bg-gradient-to-b from-primary/5 via-background to-background border-b">
        <div className="container mx-auto px-4 md:px-6 max-w-7xl relative z-10">
          <div className="flex flex-col items-center justify-center space-y-8 text-center">
            <div className="space-y-4 max-w-3xl">
              <h1 className="text-4xl font-extrabold tracking-tight sm:text-5xl md:text-6xl lg:text-7xl">
                Rent anything, <span className="text-primary">anywhere.</span>
              </h1>
              <p className="mx-auto max-w-[700px] text-muted-foreground md:text-xl/relaxed lg:text-base/relaxed xl:text-xl/relaxed">
                The most trusted peer-to-peer marketplace for discovering, renting, and sharing professional equipment.
              </p>
            </div>
            
            <div className="w-full max-w-2xl mx-auto">
              <form action="/equipment" className="flex items-center space-x-2 bg-background p-2 rounded-xl shadow-lg border">
                <Search className="w-5 h-5 text-muted-foreground ml-3 hidden sm:block" />
                <Input 
                  name="q"
                  placeholder="What do you need to rent? (e.g. Camera, Drone, Tractor)" 
                  className="border-0 shadow-none focus-visible:ring-0 text-base flex-1"
                />
                <Button type="submit" size="lg" className="rounded-lg px-8">
                  Search
                </Button>
              </form>
            </div>
            
            <div className="flex flex-wrap items-center justify-center gap-4 text-sm text-muted-foreground pt-4">
              <span className="flex items-center"><Shield className="w-4 h-4 mr-1" /> Secure Payments</span>
              <span className="flex items-center"><Zap className="w-4 h-4 mr-1" /> Instant Booking</span>
              <span className="flex items-center"><MapPin className="w-4 h-4 mr-1" /> Local Pickup</span>
            </div>
          </div>
        </div>
        
        {/* Background decorative elements */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-primary/5 rounded-full blur-3xl -z-10 pointer-events-none" />
      </section>

      {/* Featured Section */}
      <section className="w-full py-16 md:py-24 bg-background">
        <div className="container mx-auto px-4 md:px-6 max-w-7xl">
          <div className="flex flex-col sm:flex-row justify-between items-end mb-10 gap-4">
            <div>
              <h2 className="text-3xl font-bold tracking-tight">Featured Equipment</h2>
              <p className="text-muted-foreground mt-2">Discover popular items available to rent today.</p>
            </div>
            <Button variant="outline" asChild>
              <Link href="/equipment">View All Items</Link>
            </Button>
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 md:gap-8">
            {featuredItems.map((item) => (
              <Card key={item.id} className="flex flex-col overflow-hidden group border-muted/60 hover:border-primary/50 transition-colors shadow-sm hover:shadow-md">
                <CardHeader className="p-0">
                  <div className="relative aspect-[4/3] overflow-hidden bg-muted">
                    {item.photos && item.photos.length > 0 ? (
                      <img 
                        src={item.photos[0].photo_url} 
                        alt={item.title} 
                        className="object-cover w-full h-full transition-transform duration-300 group-hover:scale-105" 
                      />
                    ) : (
                      <div className="flex items-center justify-center w-full h-full text-muted-foreground bg-secondary/50">
                        No image available
                      </div>
                    )}
                    <div className="absolute top-3 right-3 bg-background/90 backdrop-blur-sm px-3 py-1 rounded-full text-sm font-bold shadow-sm">
                      ${item.daily_rate}/day
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="flex-1 p-5">
                  <CardTitle className="text-xl line-clamp-1 mb-2 group-hover:text-primary transition-colors">
                    {item.title}
                  </CardTitle>
                  <p className="text-sm text-muted-foreground line-clamp-2">
                    {item.description}
                  </p>
                </CardContent>
                <CardFooter className="p-5 pt-0 border-t border-border/50 mt-auto flex justify-between items-center bg-muted/10">
                  <span className="text-xs text-muted-foreground flex items-center">
                    <MapPin className="w-3 h-3 mr-1" /> Local
                  </span>
                  <Link href={`/equipment/${item.id}`} className="text-sm font-medium text-primary hover:underline">
                    View Details
                  </Link>
                </CardFooter>
              </Card>
            ))}
            {featuredItems.length === 0 && (
              <div className="col-span-full py-20 text-center border-2 border-dashed rounded-xl border-muted">
                <h3 className="text-lg font-medium">No items found</h3>
                <p className="text-muted-foreground mt-1 mb-4">Be the first to list your equipment on our platform.</p>
                <Button asChild>
                  <Link href="/equipment/new">List Your Gear</Link>
                </Button>
              </div>
            )}
          </div>
        </div>
      </section>
      
      {/* Call to Action Section */}
      <section className="w-full py-16 md:py-24 bg-primary text-primary-foreground">
        <div className="container mx-auto px-4 md:px-6 max-w-7xl text-center">
          <h2 className="text-3xl font-bold tracking-tight md:text-4xl mb-6">
            Got gear collecting dust?
          </h2>
          <p className="mx-auto max-w-[600px] text-primary-foreground/80 md:text-xl mb-8">
            Turn your idle equipment into passive income. It takes just 2 minutes to list an item.
          </p>
          <div className="flex flex-col sm:flex-row justify-center gap-4">
            <Button size="lg" variant="secondary" asChild>
              <Link href="/equipment/new">Start Earning Today</Link>
            </Button>
            <Button size="lg" variant="outline" className="bg-transparent border-primary-foreground text-primary-foreground hover:bg-primary-foreground hover:text-primary" asChild>
              <Link href="/about">Learn How It Works</Link>
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}
