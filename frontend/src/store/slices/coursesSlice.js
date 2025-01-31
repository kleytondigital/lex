import { createSlice, createAsyncThunk } from '@reduxjs/toolkit';
import api from '../../services/api';

export const fetchCourses = createAsyncThunk(
    'courses/fetchCourses',
    async() => {
        const response = await api.get('/courses');
        return response.data;
    }
);

export const updateLessonProgress = createAsyncThunk(
    'courses/updateLessonProgress',
    async({ lessonId, progress }) => {
        const response = await api.post(`/lessons/${lessonId}/progress`, progress);
        return response.data;
    }
);

const coursesSlice = createSlice({
    name: 'courses',
    initialState: {
        items: [],
        currentCourse: null,
        progress: {},
        loading: false,
        error: null,
    },
    reducers: {},
    extraReducers: (builder) => {
        builder
            .addCase(fetchCourses.pending, (state) => {
                state.loading = true;
            })
            .addCase(fetchCourses.fulfilled, (state, action) => {
                state.loading = false;
                state.items = action.payload;
            })
            .addCase(fetchCourses.rejected, (state, action) => {
                state.loading = false;
                state.error = action.error.message;
            })
            .addCase(updateLessonProgress.fulfilled, (state, action) => {
                const { lessonId, progress } = action.payload;
                state.progress[lessonId] = progress;
            });
    },
});

export default coursesSlice.reducer;