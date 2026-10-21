#define COBJMACROS
#include <stddef.h>
#include <windows.h>
#include <wbemidl.h>

static const CLSID fixture_clsid = {
    0x7c0f18e5,
    0x447b,
    0x4a33,
    {0x9e, 0x5a, 0xa8, 0xb8, 0x3c, 0x9c, 0x5d, 0x41},
};

typedef struct {
    IWbemProviderInit provider;
    IWbemEventProvider event_provider;
    LONG references;
} provider_object;

typedef struct {
    IClassFactory factory;
    LONG references;
} provider_factory;

static LONG object_count;

static HRESULT STDMETHODCALLTYPE provider_query(
    IWbemProviderInit *self, REFIID iid, void **out) {
    provider_object *object = (provider_object *)self;
    if (out == NULL) {
        return E_POINTER;
    }
    *out = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) ||
        IsEqualIID(iid, &IID_IWbemProviderInit)) {
        *out = self;
        IWbemProviderInit_AddRef(self);
        return S_OK;
    }
    if (IsEqualIID(iid, &IID_IWbemEventProvider)) {
        *out = &object->event_provider;
        IWbemProviderInit_AddRef(self);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE provider_add_ref(IWbemProviderInit *self) {
    provider_object *object = (provider_object *)self;
    return (ULONG)InterlockedIncrement(&object->references);
}

static ULONG STDMETHODCALLTYPE provider_release(IWbemProviderInit *self) {
    provider_object *object = (provider_object *)self;
    LONG references = InterlockedDecrement(&object->references);
    if (references == 0) {
        InterlockedDecrement(&object_count);
        HeapFree(GetProcessHeap(), 0, object);
    }
    return (ULONG)references;
}

static HRESULT STDMETHODCALLTYPE provider_initialize(
    IWbemProviderInit *self, LPWSTR user, LONG flags, LPWSTR name_space,
    LPWSTR locale, IWbemServices *services, IWbemContext *context,
    IWbemProviderInitSink *sink) {
    (void)self;
    (void)user;
    (void)flags;
    (void)name_space;
    (void)locale;
    (void)services;
    (void)context;
    if (sink == NULL) {
        return WBEM_E_INVALID_PARAMETER;
    }
    IWbemProviderInitSink_SetStatus(sink, WBEM_S_INITIALIZED, 0);
    return WBEM_S_NO_ERROR;
}

static IWbemProviderInitVtbl provider_vtable = {
    provider_query,
    provider_add_ref,
    provider_release,
    provider_initialize,
};

static provider_object *object_from_event(IWbemEventProvider *event_provider) {
    return (provider_object *)((char *)event_provider -
                               offsetof(provider_object, event_provider));
}

static HRESULT STDMETHODCALLTYPE event_query(
    IWbemEventProvider *event_provider, REFIID iid, void **out) {
    return provider_query(&object_from_event(event_provider)->provider, iid, out);
}

static ULONG STDMETHODCALLTYPE event_add_ref(
    IWbemEventProvider *event_provider) {
    return provider_add_ref(&object_from_event(event_provider)->provider);
}

static ULONG STDMETHODCALLTYPE event_release(
    IWbemEventProvider *event_provider) {
    return provider_release(&object_from_event(event_provider)->provider);
}

static HRESULT STDMETHODCALLTYPE event_provide(
    IWbemEventProvider *event_provider, IWbemObjectSink *sink, LONG flags) {
    (void)event_provider;
    (void)sink;
    (void)flags;
    return WBEM_S_NO_ERROR;
}

static IWbemEventProviderVtbl event_vtable = {
    event_query,
    event_add_ref,
    event_release,
    event_provide,
};

static HRESULT STDMETHODCALLTYPE factory_query(
    IClassFactory *self, REFIID iid, void **out) {
    if (out == NULL) {
        return E_POINTER;
    }
    *out = NULL;
    if (IsEqualIID(iid, &IID_IUnknown) ||
        IsEqualIID(iid, &IID_IClassFactory)) {
        *out = self;
        IClassFactory_AddRef(self);
        return S_OK;
    }
    return E_NOINTERFACE;
}

static ULONG STDMETHODCALLTYPE factory_add_ref(IClassFactory *self) {
    provider_factory *factory = (provider_factory *)self;
    return (ULONG)InterlockedIncrement(&factory->references);
}

static ULONG STDMETHODCALLTYPE factory_release(IClassFactory *self) {
    provider_factory *factory = (provider_factory *)self;
    LONG references = InterlockedDecrement(&factory->references);
    if (references == 0) {
        HeapFree(GetProcessHeap(), 0, factory);
    }
    return (ULONG)references;
}

static HRESULT STDMETHODCALLTYPE factory_create(
    IClassFactory *self, IUnknown *outer, REFIID iid, void **out) {
    provider_object *object;
    HRESULT result;
    (void)self;
    if (outer != NULL) {
        return CLASS_E_NOAGGREGATION;
    }
    object = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*object));
    if (object == NULL) {
        return E_OUTOFMEMORY;
    }
    object->provider.lpVtbl = &provider_vtable;
    object->event_provider.lpVtbl = &event_vtable;
    object->references = 1;
    InterlockedIncrement(&object_count);
    result = IWbemProviderInit_QueryInterface(&object->provider, iid, out);
    IWbemProviderInit_Release(&object->provider);
    return result;
}

static HRESULT STDMETHODCALLTYPE factory_lock(IClassFactory *self, BOOL lock) {
    (void)self;
    if (lock) {
        InterlockedIncrement(&object_count);
    } else {
        InterlockedDecrement(&object_count);
    }
    return S_OK;
}

static IClassFactoryVtbl factory_vtable = {
    factory_query,
    factory_add_ref,
    factory_release,
    factory_create,
    factory_lock,
};

HRESULT WINAPI DllGetClassObject(
    REFCLSID clsid, REFIID iid, void **out) {
    provider_factory *factory;
    HRESULT result;
    if (!IsEqualCLSID(clsid, &fixture_clsid)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    factory = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*factory));
    if (factory == NULL) {
        return E_OUTOFMEMORY;
    }
    factory->factory.lpVtbl = &factory_vtable;
    factory->references = 1;
    result = IClassFactory_QueryInterface(&factory->factory, iid, out);
    IClassFactory_Release(&factory->factory);
    return result;
}

HRESULT WINAPI DllCanUnloadNow(void) {
    return object_count == 0 ? S_OK : S_FALSE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        HANDLE marker;
        DisableThreadLibraryCalls(instance);
        marker = CreateFileW(
            L"C:\\Windows\\Temp\\remoteexec-wmi-provider.marker",
            GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (marker != INVALID_HANDLE_VALUE) {
            CloseHandle(marker);
        }
    }
    return TRUE;
}
