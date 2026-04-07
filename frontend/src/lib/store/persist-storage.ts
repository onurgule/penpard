import { createJSONStorage, type PersistStorage, type StateStorage } from 'zustand/middleware';

function getLocalStorage(): StateStorage {
    return {
        getItem: (name) => window.localStorage.getItem(name),
        setItem: (name, value) => window.localStorage.setItem(name, value),
        removeItem: (name) => window.localStorage.removeItem(name),
    };
}

export function createSafeLocalStorage<S>(): PersistStorage<S> | undefined {
    if (typeof window === 'undefined') {
        return undefined;
    }

    const storage = createJSONStorage<S>(() => getLocalStorage());

    if (!storage) {
        return undefined;
    }

    return {
        getItem: (name) => {
            try {
                return storage.getItem(name);
            } catch (error) {
                if (typeof window !== 'undefined') {
                    window.localStorage.removeItem(name);
                }
                console.warn(`[persist] Removed corrupted storage entry "${name}"`, error);
                return null;
            }
        },
        setItem: (name, value) => storage.setItem(name, value),
        removeItem: (name) => storage.removeItem(name),
    };
}
