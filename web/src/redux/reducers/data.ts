import { createSlice, PayloadAction } from "@reduxjs/toolkit";

/* ================================State======================================*/
let initialState = {
    example: false
};

/* ================================Slice======================================*/
const dataSlice = createSlice({
    name: "data",
    initialState,
    reducers: {
        exampleAction(state, _action: PayloadAction<any>) {
            state.example = true;
        },
    }
});


/* ================================Exports======================================*/

export const {
    exampleAction,
} = dataSlice.actions;

export default dataSlice.reducer;