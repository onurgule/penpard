import MissionControlClient from './MissionControlClient';

// Required for static export with dynamic routes
// Return a placeholder - actual routing happens client-side
export function generateStaticParams() {
    return [{ id: '_' }];
}

export default function MissionControlPage() {
    return <MissionControlClient />;
}
