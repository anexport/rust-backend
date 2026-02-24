export const dynamic = 'force-dynamic';
import { fetchServer } from '@/lib/server';
import { Button } from '@/components/ui/button';
import Link from 'next/link';

interface EquipmentItem {
  id: string;
  title: string;
  description: string;
  daily_rate: number;
  condition: string;
  location: string;
  photos: { photo_url: string }[];
}

export default async function EquipmentDetailsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const res = await fetchServer(`/api/equipment/${id}`);
  
  if (!res.ok) {
    return <div className="p-8 text-center text-red-500">Equipment not found.</div>;
  }

  const item: EquipmentItem = await res.json();

  return (
    <main className="container mx-auto py-10 px-4 md:px-6 max-w-7xl">
      <div className="mb-6">
        <Link href="/equipment" className="text-sm text-muted-foreground hover:underline">
          &larr; Back to Listings
        </Link>
      </div>
      
      <div className="grid md:grid-cols-2 gap-8">
        <div>
           {item.photos && item.photos.length > 0 ? (
             <img 
               src={item.photos[0].photo_url} 
               alt={item.title} 
               className="w-full h-auto object-cover rounded-lg shadow-sm" 
             />
           ) : (
             <div className="w-full aspect-square bg-muted rounded-lg shadow-sm flex items-center justify-center text-muted-foreground">
               No image provided
             </div>
           )}
        </div>
        
        <div className="space-y-6">
          <div>
            <h1 className="text-3xl font-bold mb-2">{item.title}</h1>
            <div className="text-2xl font-bold text-primary">${item.daily_rate} / day</div>
          </div>
          
          <div className="space-y-2">
            <h3 className="font-semibold">Condition</h3>
            <p className="capitalize text-muted-foreground">{item.condition}</p>
          </div>

          <div className="space-y-2">
            <h3 className="font-semibold">Location</h3>
            <p className="text-muted-foreground">{item.location}</p>
          </div>

          <div className="space-y-2">
            <h3 className="font-semibold">Description</h3>
            <p className="text-muted-foreground whitespace-pre-wrap">{item.description}</p>
          </div>
          
          <div className="pt-6 border-t flex space-x-4">
             <Button className="w-full" asChild>
               <Link href={`/messages/new?equipment_id=${item.id}`}>Contact Owner</Link>
             </Button>
          </div>
        </div>
      </div>
    </main>
  );
}
