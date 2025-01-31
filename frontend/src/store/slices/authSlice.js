import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../services/api';

export const login = createAsyncThunk(
    'auth/login',
    async(credentials) => {
        const response = await api.post('/auth/login', credentials);
        localStorage.setItem('token', response.data.token);
        return response.data;
    }
);

const initialState = {
    user: null,
    loading: true,
    error: null,
};

const authSlice = createSlice({
    name: 'auth',
    initialState,
    reducers: {
        setUser: (state, action) => {
            state.user = action.payload;
            state.loading = false;
        },
        startLoading: (state) => {
            state.loading = true;
        },
        setError: (state, action) => {
            state.error = action.payload;
            state.loading = false;
        },
        clearError: (state) => {
            state.error = null;
        },
        logout: (state) => {
            state.user = null;
            state.loading = false;
            state.error = null;
        },
    },
    extraReducers: (builder) => {
        builder
            .addCase(login.pending, (state) => {
                state.loading = true;
                state.error = null;
            })
            .addCase(login.fulfilled, (state, action) => {
                state.loading = false;
                state.isAuthenticated = true;
                state.user = action.payload.user;
                state.token = action.payload.token;
            })
            .addCase(login.rejected, (state, action) => {
                state.loading = false;
                state.error = action.error.message;
            });
    },
});

export const {
    setUser,
    startLoading,
    setError,
    clearError,
    logout
} = authSlice.actions;

export default authSlice.reducer;